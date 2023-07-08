#ifndef __CONFIG_H__
#define __CONFIG_H__

#include "pico/cyw43_arch.h"

#define COUNTRY_CODE_0                  'U'
#define COUNTRY_CODE_1                  'S'

#define WIFI_AUTH                       CYW43_AUTH_WPA2_AES_PSK
#define WIFI_PASSWORD                   "cloudywindow678"
#define FIRMWARE_VERSION                "0.1.0" // Your version
#define WIFI_SSID                       "NETGEAR84"

/**
* 1 - Thermostat
* 2 - Desk
*/
#define SERVICE_TYPE                    2

// TCP SERVER

#define TCP_SERVER_PORT                 6969
#define TCP_SERVER_BUF_SIZE             2048
#define TCP_SERVER_POLL_TIME_S          5
#define TCP_SERVER_MAX_CLIENTS          5
#define TCP_SERVER_INACTIVE_TIME_S      120

// ENCRYPTION
// To disable encryption do not define this variable
//#define AES_ENCRYPTION_KEY              "32-BYTES-KEY-IN-BASE64"

#endif