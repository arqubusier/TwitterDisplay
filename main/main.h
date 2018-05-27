/*
  Made from espressif OpenSSL server Example
*/

#ifndef _MAIN_H_
#define _MAIN_H_

#include "sdkconfig.h"

/* The examples use simple WiFi configuration that you can set via
   'make menuconfig'.

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
*/
#define EXAMPLE_WIFI_SSID               CONFIG_WIFI_SSID
#define EXAMPLE_WIFI_PASS               CONFIG_WIFI_PASSWORD

#define SERVER_TASK_NAME "server_task"
#define SERVER_TASK_STACK_WORDS 10240
#define SERVER_TASK_PRIORITY    8

#define SERVER_TASK_RECV_BUF_LEN       1024

#define SERVER_TASK_LOCAL_TCP_PORT     443

#endif

