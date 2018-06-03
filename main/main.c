/* OpenSSL server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include "main.h"

#include <string.h>

#include "openssl/ssl.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"

#include "nvs_flash.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"

static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
const static int CONNECTED_BIT = BIT0;

const static char *TAG = "Openssl_example";

#define START_PAGE "HTTP/1.1 200 OK\r\n" \
"Content-Type: text/html\r\n" \
"Content-Length: 297 \r\n\r\n" \
"<html>\r\n" \
"<head>\r\n" \
"<title>Esp Display</title></head><body>\r\n" \
"<form method=\"post\">\r\n" \
"  Text to display:<br>\r\n" \
"  <input type=\"text\" name=\"text\" value=\"\"><br>\r\n" \
"  Password:<br>\r\n" \
"  <input type=\"password\" name=\"password\" value=\"\"><br><br>\r\n" \
"  <input type=\"submit\" value=\"Submit\">\r\n" \
"</form>\r\n" \
"</body>\r\n" \
"</html>\r\n" \
"\r\n"

char RESPONSE_HEADER1[] = "HTTP/1.1 ";
char RESPONSE_HEADER2[] = " OK\r\n"
  "Content-Type: text/html\r\n"
  "Content-Length:";
char RESPONSE_HEADER3[] = " \r\n\r\n"
  "<html>\r\n"
  "<head>\r\n";
char RESPONSE_TOP[] = "<title>Esp Display</title></head><body>\r\n"
  "<form method=\"post\">\r\n"
  "  Text to display:<br>\r\n"
  "  <input type=\"text\" name=\"text\" value=\"\"><br>\r\n"
  "  Password:<br>\r\n"
  "  <input type=\"password\" name=\"password\" value=\"\"><br><br>\r\n"
  "  <input type=\"submit\" value=\"Submit\"><br><br>\r\n";
char RESPONSE_BOTTOM[] = "</form>\r\n"
  "</body>\r\n"
  "</html>\r\n"
  "\r\n";

char STATUS_HEAD[] = "Status: ";
char STATUS_NO_TEXT[] = " text field must be non-empty";
char STATUS_NO_PASSWORD[] = " password field must be non-empty";
char STATUS_WRONG_PASSWORD[] = " wrong password";
char STATUS_CORRECT_PASSWORD[] = " text set to: ";

typedef struct {
  int success;
  char* start;
  size_t len;
} param_res;

param_res find_param(const char* buf, const char* param){
  param_res res = {0, strstr(buf, param), 0};

  if (res.start != NULL){
    res.start += strnlen(param, MAX_STR_LEN);
    res.success = 1;
    char *stop = strpbrk(res.start, "&");
    if (stop == NULL){
      res.len = strnlen(res.start, MAX_STR_LEN);
    }
    else{
        res.len = stop - res.start;
    }
  }
  return res;
}

size_t number_str_len(size_t number){
  return (number < 10)? 1
    :(number < 100)? 2
    :(number < 1000)? 3
    :(number < 10000)? 4
    :(number < 100000)? 5
    :(number < 1000000)? 6
    :(number < 10000000)? 7
    :(number < 100000000)? 8
    :9;
}

size_t min(size_t lhs, size_t rhs){
  if (lhs < rhs)
    return lhs;
  return rhs;
}

/*
 Copy a maximum of count+1 chars from src string dest,
 the latter offset by the value pointed to by counter.
 The last character to be copied from src is always
 replaced by a null character.

 counter is incremented by the number of copied elements,
 excluding the null character.

 if destsz is less than counter + count,
 only max(count, destsz - counter)
 chars will be copied.
*/
void append_str(char* dest, const char* src, size_t count, size_t destsz, size_t* counter){
  size_t bytes_to_copy = min(count, destsz - *counter);
  if (bytes_to_copy > 0){
    strncpy(dest+*counter, src, bytes_to_copy);
    dest[*counter+bytes_to_copy-1]='\0';
    counter+=bytes_to_copy-1;
  }
}

size_t size(char** strs, size_t n_strs){
  size_t i=0;
  size_t acc=0;

  for (; i<n_strs; ++i){
    acc += strlen(strs[i]);
  }
  return acc;
}

void join(char* dest, char** strs, size_t n_strs, size_t destsz){
  size_t i=0;
  size_t strsz = 0;
  size_t acc = 0;

  for (; i<n_strs; ++i){
    strsz = strlen(strs[i]);
    if (acc + strsz > destsz)
      strsz = destsz - acc;
    memcpy(dest + acc, strs[i], strsz);
    acc += strsz;
  }
}

static void server_task(void *p)
{
    int ret;

    SSL_CTX *ctx;
    SSL *ssl;

    int sockfd, new_sockfd;
    socklen_t addr_len;
    struct sockaddr_in sock_addr;

    char recv_buf[SERVER_TASK_RECV_BUF_LEN];

    const char start_data[] = START_PAGE;
    const int start_bytes = sizeof(start_data);

    extern const unsigned char cacert_pem_start[] asm("_binary_cacert_pem_start");
    extern const unsigned char cacert_pem_end[]   asm("_binary_cacert_pem_end");
    const unsigned int cacert_pem_bytes = cacert_pem_end - cacert_pem_start;

    extern const unsigned char prvtkey_pem_start[] asm("_binary_prvtkey_pem_start");
    extern const unsigned char prvtkey_pem_end[]   asm("_binary_prvtkey_pem_end");
    const unsigned int prvtkey_pem_bytes = prvtkey_pem_end - prvtkey_pem_start;   

    char* header_end;
    char* body_recv;

    param_res text_param;
    param_res pass_param;

    const size_t RESPONSE_MAX_IDX = 9;
    char* response_strs[RESPONSE_MAX_IDX+1];
    size_t response_n_strs=0;
    char* response;

    char status_str[MAX_STR_LEN_INT] = {'\0'};
    char len_str[MAX_STR_LEN_INT] = {'\0'};
    char text_str[MAX_STR_LEN] = {'\0'};
    const size_t RESPONSE_BODY_IDX = 5;


    ESP_LOGI(TAG, "SSL server context create ......");
    /* For security reasons, it is best if you can use
       TLSv1_2_server_method() here instead of TLS_server_method().
       However some old browsers may not support TLS v1.2.
    */
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ESP_LOGI(TAG, "failed");
        goto failed1;
    }
    ESP_LOGI(TAG, "OK");

    ESP_LOGI(TAG, "SSL server context set own certification......");
    ret = SSL_CTX_use_certificate_ASN1(ctx, cacert_pem_bytes, cacert_pem_start);
    if (!ret) {
        ESP_LOGI(TAG, "failed");
        goto failed2;
    }
    ESP_LOGI(TAG, "OK");

    ESP_LOGI(TAG, "SSL server context set private key......");
    ret = SSL_CTX_use_PrivateKey_ASN1(0, ctx, prvtkey_pem_start, prvtkey_pem_bytes);
    if (!ret) {
        ESP_LOGI(TAG, "failed");
        goto failed2;
    }
    ESP_LOGI(TAG, "OK");

    ESP_LOGI(TAG, "SSL server create socket ......");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        ESP_LOGI(TAG, "failed");
        goto failed2;
    }
    ESP_LOGI(TAG, "OK");

    ESP_LOGI(TAG, "SSL server socket bind ......");
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = 0;
    sock_addr.sin_port = htons(SERVER_TASK_LOCAL_TCP_PORT);
    ret = bind(sockfd, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
    if (ret) {
        ESP_LOGI(TAG, "failed");
        goto failed3;
    }
    ESP_LOGI(TAG, "OK");

    ESP_LOGI(TAG, "SSL server socket listen ......");
    ret = listen(sockfd, 32);
    if (ret) {
        ESP_LOGI(TAG, "failed");
        goto failed3;
    }
    ESP_LOGI(TAG, "OK");

reconnect:
    ESP_LOGI(TAG, "SSL server create ......");
    ssl = SSL_new(ctx);
    if (!ssl) {
        ESP_LOGI(TAG, "failed");
        goto failed3;
    }
    ESP_LOGI(TAG, "OK");

    ESP_LOGI(TAG, "SSL server socket accept client ......");
    new_sockfd = accept(sockfd, (struct sockaddr *)&sock_addr, &addr_len);
    if (new_sockfd < 0) {
        ESP_LOGI(TAG, "failed" );
        goto failed4;
    }
    ESP_LOGI(TAG, "OK");

    SSL_set_fd(ssl, new_sockfd);

    ESP_LOGI(TAG, "SSL server accept client ......");
    ret = SSL_accept(ssl);
    if (!ret) {
        ESP_LOGI(TAG, "failed");
        goto failed5;
    }
    ESP_LOGI(TAG, "OK");

    ESP_LOGI(TAG, "SSL server read message ......");
    do {
        memset(recv_buf, 0, SERVER_TASK_RECV_BUF_LEN);
        ret = SSL_read(ssl, recv_buf, SERVER_TASK_RECV_BUF_LEN - 1);
        if (ret <= 0) {
            break;
        }
        ESP_LOGI(TAG, "SSL read: %s", recv_buf);

        if (strstr(recv_buf, "GET ") &&
            strstr(recv_buf, " HTTP/1.1")) {
            ESP_LOGI(TAG, "SSL get matched message");
            ESP_LOGI(TAG, "SSL write message");
            ret = SSL_write(ssl, start_data, start_bytes);
            if (ret > 0) {
                ESP_LOGI(TAG, "OK");
            } else {
                ESP_LOGI(TAG, "error");
            }
            break;
        }
        else if (strstr(recv_buf, "POST ") &&
                  strstr(recv_buf, " HTTP/1.1")){
          ESP_LOGI(TAG, "SSL POST response");
          header_end = strstr(recv_buf, "\r\n\r\n");
          if (header_end != NULL){
            body_recv = header_end+4;
            text_param = find_param(body_recv, "text=");
            pass_param = find_param(body_recv, "password=");

            response_n_strs=0;
            response_strs[response_n_strs++] = RESPONSE_HEADER1;
            response_strs[response_n_strs++] = status_str;
            response_strs[response_n_strs++] = RESPONSE_HEADER2;
            response_strs[response_n_strs++] = len_str;
            response_strs[response_n_strs++] = RESPONSE_HEADER3;
            response_strs[response_n_strs++] = RESPONSE_TOP;
            response_strs[response_n_strs++] = STATUS_HEAD;

            if (text_param.len == 0){
              response_strs[response_n_strs++] = STATUS_NO_TEXT;
            }
            else if(pass_param.len == 0){
              response_strs[response_n_strs++] = STATUS_NO_PASSWORD;
            }
            else {
              if( sizeof(PASSWORD)-1 == pass_param.len
                  && (strncmp(PASSWORD, pass_param.start, sizeof(PASSWORD)) == 0) ){
                response_strs[response_n_strs++] = STATUS_CORRECT_PASSWORD;
                size_t copy_sz = min(text_param.len, MAX_STR_LEN);
                strncpy(text_str, text_param.start, copy_sz);
                text_str[(copy_sz==0)? 0: copy_sz - 1] = '\0';
                response_strs[response_n_strs++] = text_str;
              }
              else{
                response_strs[response_n_strs++] = STATUS_WRONG_PASSWORD;
              }
            }
            response_strs[response_n_strs++] = RESPONSE_BOTTOM;
            size_t content_len = size(response_strs+RESPONSE_BODY_IDX
                                      , response_n_strs-RESPONSE_BODY_IDX );
            snprintf(status_str, MAX_STR_LEN_INT, "%d", 400);
            snprintf(len_str, MAX_STR_LEN_INT, "%d", content_len);

            size_t response_sz = size(response_strs, response_n_strs);
            response = malloc(response_sz);
            join(response, response_strs, response_n_strs, response_sz);

            ret = SSL_write(ssl, response, strlen(response));
            free(response);
            response=NULL;;

            if (ret > 0) {
              ESP_LOGI(TAG, "OK");
            } else {
              ESP_LOGI(TAG, "error");
            }
          }
        }
    } while (1);
    
    SSL_shutdown(ssl);
failed5:
    close(new_sockfd);
    new_sockfd = -1;
failed4:
    SSL_free(ssl);
    ssl = NULL;
    goto reconnect;
failed3:
    close(sockfd);
    sockfd = -1;
failed2:
    SSL_CTX_free(ctx);
    ctx = NULL;
failed1:
    vTaskDelete(NULL);
    return ;
} 

static void openssl_server_init(void)
{
    int ret;
    xTaskHandle openssl_handle;

    ret = xTaskCreate(server_task,
                      SERVER_TASK_NAME,
                      SERVER_TASK_STACK_WORDS,
                      NULL,
                      SERVER_TASK_PRIORITY,
                      &openssl_handle); 

    if (ret != pdPASS)  {
        ESP_LOGI(TAG, "create task %s failed", SERVER_TASK_NAME);
    }
}

static esp_err_t wifi_event_handler(void *ctx, system_event_t *event)
{
    switch(event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
        openssl_server_init();
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        /* This is a workaround as ESP32 WiFi libs don't currently
           auto-reassociate. */
        esp_wifi_connect(); 
        xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
        break;
    default:
        break;
    }
    return ESP_OK;
}

static void wifi_conn_init(void)
{
    tcpip_adapter_init();
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK( esp_event_loop_init(wifi_event_handler, NULL) );
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = EXAMPLE_WIFI_SSID,
            .password = EXAMPLE_WIFI_PASS,
        },
    };
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    ESP_LOGI(TAG, "start the WIFI SSID:[%s] password:[%s]\n", EXAMPLE_WIFI_SSID, EXAMPLE_WIFI_PASS);
    ESP_ERROR_CHECK( esp_wifi_start() );
}

void app_main(void)
{
    ESP_ERROR_CHECK( nvs_flash_init() );
    wifi_conn_init();
}
