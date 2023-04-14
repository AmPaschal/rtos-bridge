/**
 * Rtos Bridge
*/
#include <sys/time.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include "time.h"
#include "freertos-bridge.h"

#define BUFFER_SIZE 20
#define ETH_IP_TYPE 0x0800
#define FUZZ_MODE 0

#define TAP 1
#define TUN 2

#define CONFIG_NET_INTERFACE TUN

static int data_socket;
static int tun_fd;


struct SocketPackage {
    int domain;
    int type;
    int protocol;
};

struct AcceptPackage {
    int sockfd;
};

struct BindPackage {
    int sockfd;
    union {
        struct sockaddr_in addr;
        struct sockaddr_in6 addr6;
    };
    socklen_t addrlen;
};

struct ListenPackage {
    int sockfd;
    int backlog;
};

struct WritePackage {
    int sockfd;
    size_t count;
};

struct SendToPackage {
    int sockfd;
    int flags;
    union {
        struct sockaddr_in addr;
        struct sockaddr_in6 addr6;
    };
    socklen_t addrlen;
};

struct ReadPackage {
    int sockfd;
    size_t count;
};

struct RecvFromPackage {
    int sockfd;
    size_t count;
    int flags;
};

struct ClosePackage {
    int sockfd;
};

struct SyscallPackage {
    char syscallId[20];
    int bufferedMessage;
    size_t bufferedCount;
    void *buffer;
    union {
        struct SocketPackage socketPackage;
        struct BindPackage bindPackage;
        struct ListenPackage listenPackage;
        struct AcceptPackage acceptPackage;
        struct BindPackage connectPackage;
        struct WritePackage writePackage;
        struct SendToPackage sendToPackage;
        struct ClosePackage closePackage;
        struct ReadPackage readPackage;
        struct RecvFromPackage recvFromPackage;
    };
};

struct AcceptResponsePackage {
    union {
        struct sockaddr_in addr;
        struct sockaddr_in6 addr6;
    };
    socklen_t addrlen;
};

struct SyscallResponsePackage {
    int result;
    union {
        struct AcceptResponsePackage acceptResponse;
    };
};

struct EthernetHeader {
    uint8_t destinationAddress[6];
    uint8_t sourceAddress[6];
    uint16_t frameType;
};

struct EthernetFrame {
    struct EthernetHeader ethernetHeader;
    void *payload;
};

static void print_hex(unsigned char * bin_data, size_t len)

{
    size_t i;

    for( i = 0; i < len; ++i )
    {
        printf( "%.2X ", bin_data[ i ] );
    }

    printf( "\n" );
}


int send_syscall(struct SyscallPackage *syscallPackage, struct SyscallResponsePackage *syscallResponse);


static int freertos_socket(void *userdata, int domain, int type, int protocol) {
    print_current_time("socket_create");
    printf("Creating a freertos socket\n");

    struct SocketPackage socketPackage;
    socketPackage.domain = domain;
    socketPackage.type = type;
    socketPackage.protocol = protocol;

    struct SyscallPackage syscallPackage;
    strcpy(syscallPackage.syscallId, "socket_create\0");
    syscallPackage.socketPackage = socketPackage;


    struct SyscallResponsePackage syscallResponse;

    int result = send_syscall(&syscallPackage, &syscallResponse);

    if (result == -1) {
        return 0;
    }

    return syscallResponse.result;
}

static int freertos_bind (void *userdata, int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

    print_current_time("socket_bind");

    struct BindPackage bindPackage;

    bindPackage.sockfd = sockfd;
    memcpy(&bindPackage.addr, addr, sizeof(struct sockaddr));
    bindPackage.addrlen = addrlen;

    struct SyscallPackage syscallPackage;
    strcpy(syscallPackage.syscallId, "socket_bind\0");
    syscallPackage.bindPackage = bindPackage;

    struct SyscallResponsePackage syscallResponse;

    int result = send_syscall(&syscallPackage, &syscallResponse);

    if (result == -1) {
        return 10;
    }

    return syscallResponse.result;
}

static int freertos_listen (void *userdata, int sockfd, int backlog) {

    print_current_time("socket_listen");
    struct ListenPackage listenPackage;

    listenPackage.sockfd = sockfd;
    listenPackage.backlog = backlog;

    struct SyscallPackage syscallPackage;
    strcpy(syscallPackage.syscallId, "socket_listen\0");
    syscallPackage.listenPackage = listenPackage;

    struct SyscallResponsePackage syscallResponse;

    int result = send_syscall(&syscallPackage, &syscallResponse);

    if (result == -1) {
        return 10;
    }

    return syscallResponse.result;
}

static int freertos_accept (void *userdata, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {

    print_current_time("socket_accept");

    struct AcceptPackage acceptPackage;

    acceptPackage.sockfd = sockfd;

    struct SyscallPackage syscallPackage;
    strcpy(syscallPackage.syscallId, "socket_accept\0");
    syscallPackage.acceptPackage = acceptPackage;

    struct SyscallResponsePackage syscallResponse;

    int result = send_syscall(&syscallPackage, &syscallResponse);

    if (result == -1 || syscallResponse.result <= 0) {
        return 0;
    }

    printf("Printing returned accept ip addr...\n");
    print_hex((unsigned char *) &syscallResponse.acceptResponse.addr, syscallResponse.acceptResponse.addrlen);

    memcpy(addr, &(syscallResponse.acceptResponse.addr), syscallResponse.acceptResponse.addrlen);
    *addrlen = syscallResponse.acceptResponse.addrlen;

    return syscallResponse.result;
}


static int freertos_connect (void *userdata, int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

    print_current_time("socket_connect");

    struct BindPackage connectPackage;

    connectPackage.sockfd = sockfd;
    memcpy(&connectPackage.addr, addr, addrlen);
    connectPackage.addrlen = addrlen;

    struct SyscallPackage syscallPackage;
    strcpy(syscallPackage.syscallId, "socket_connect\0");
    syscallPackage.connectPackage = connectPackage;

    struct SyscallResponsePackage syscallResponse;

    int result = send_syscall(&syscallPackage, &syscallResponse);

    if (result == -1) {
        return 0;
    }

    return syscallResponse.result;
}

static int freertos_close(void *userdata, int fd) {

    print_current_time("socket_close");

    struct ClosePackage closePackage;
    closePackage.sockfd = fd;

    struct SyscallPackage syscallPackage;
    strcpy(syscallPackage.syscallId, "socket_close\0");
    syscallPackage.closePackage = closePackage;

    struct SyscallResponsePackage syscallResponse;

    int result = send_syscall(&syscallPackage, &syscallResponse);

    if (result == -1 || syscallResponse.result != 0) {
        return -1;
    } else {
        return 0;
    }
}

static int freertos_gettimeofday(void *userdata, struct timeval *tv,
                                 			    struct timezone *tz) {
    return gettimeofday(tv, NULL);
}

static int freertos_netdev_send (void *userdata, const void *buf, size_t count) {

    print_current_time("netdev_send");

    printf("IP packet to be sent:\n");
    print_hex((unsigned char *)buf, count);
    printf("\n");

    char *data;
    size_t data_len;

    if (strncmp(getenv("TAP_INTERFACE_NAME"), "tun", 3) != 0) {
            //46:e7:d7:aa:9b:5f
        struct EthernetHeader ethernetHeader;
        uint8_t destinationAddress[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x41};
        //uint8_t sourceAddress[6] = {0x3A, 0x01, 0x49, 0xBA, 0x4C, 0xCE};
        uint8_t sourceAddress[6] = {0x46, 0xE7, 0xD7, 0xAA, 0x9B, 0x5F};

        memcpy(ethernetHeader.destinationAddress, destinationAddress, sizeof(destinationAddress));
        memcpy(ethernetHeader.sourceAddress, sourceAddress, sizeof(sourceAddress));
        ethernetHeader.frameType = htons(ETH_IP_TYPE);

        size_t ethernetHeaderSize = sizeof(struct EthernetHeader);

        data_len = count + ethernetHeaderSize;

        data = malloc(data_len);

        memcpy(data, &ethernetHeader, ethernetHeaderSize);
        memcpy(data + ethernetHeaderSize, buf, count);

        printf("Correct Ethernet frame:\n");
        print_hex((unsigned char *)data, data_len);

        if (data_len == 66 && FUZZ_MODE == 1) {
            data[17] = 0x29;
            data_len -= 11;
        } else if (data_len == 66 && FUZZ_MODE == 2) {
            data[14] = 0x4F;
        } else if (data_len == 66 && FUZZ_MODE == 3) {
            data[17] = 0x14;
            data_len -= 32;
        } else if (data_len == 2054 && FUZZ_MODE == 4) {
            data_len += 8;
            data = realloc(data, data_len);
            char *frameOffset = data + 34;
            memmove(frameOffset + 8, frameOffset, data_len - 42);
            memset(frameOffset, 0, 8);
            data[14] = 0x47;

        }
    } else {
        data = (char *) buf;
        data_len = count;

        if (FUZZ_MODE == 5) {
            data[5] = 0x01;
            data[6] = 0x00;
            data_len = count - 7;
        }
        
    }


    ssize_t ret = write(tun_fd, data, data_len);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    printf("IP packet sent at timestamp %ld.%ld\n", tv.tv_sec, tv.tv_usec);
    print_hex((unsigned char *)data, data_len);

    printf("\n");

    if (ret < 0) {
        printf("An error occurred sending ethernet frame with errno %d...\n", errno);
        return -1;
    } else if (ret != data_len) {
        printf("Incorrect ethernet frame size sent: %lu bytes...\n", ret);
        return -1;
    } else {
        printf("Ethernet frame successfully sent: %lu bytes...\n", ret);
        return 0;
    }

}

static int freertos_netdev_receive (void *userdata, void *buffer, size_t *count,
			      long long *time_usecs) {

    print_current_time("netdev_receive");

    printf("freertos_netdev_receive called...\n");

    uint8_t sutAddress[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x41};
    uint8_t hostAddress[6] = {0x46, 0xE7, 0xD7, 0xAA, 0x9B, 0x5F};
    size_t ethernetHeaderSize = sizeof(struct EthernetHeader);

    for (;;) {
        char *tempBuffer = malloc(*count);

        int numRead = read(tun_fd, tempBuffer, *count);

        if (numRead < 0) {
            printf("Error reading from tun_fd\n");
            free(tempBuffer);
            return -1;
        } else if (numRead < ethernetHeaderSize) {
            printf("Not up to full ethernet frame read\n");
        }

        char *ip_bytes;
        size_t ip_bytes_len;

        if (strncmp(getenv("TAP_INTERFACE_NAME"), "tun", 3) != 0) { // If TAP, we are expecting an ethernet frame. We verify that the mac addresses match
            if (memcmp(tempBuffer, hostAddress, 6) != 0 || memcmp(tempBuffer + 6, sutAddress, 6) != 0) {

                printf("Not outbound frame\n");
                print_hex((unsigned char *)tempBuffer, numRead);
                printf("\n");
                free(tempBuffer);
                continue;
            }

            ip_bytes = tempBuffer + ethernetHeaderSize;
            ip_bytes_len = numRead - ethernetHeaderSize;
        } else {
            ip_bytes = tempBuffer;
            ip_bytes_len = numRead;
        }

        printf("Found outbound frame\n");
        print_hex((unsigned char *)tempBuffer, numRead);
        printf("\n");

        memcpy(buffer, ip_bytes, ip_bytes_len);
        *count = ip_bytes_len;

        struct timeval tv;
        gettimeofday(&tv, NULL);
        *time_usecs = 1000000 * (uint64_t)tv.tv_sec + tv.tv_usec;

        free(tempBuffer);

        return 0;

    }

}


static ssize_t freertos_write(void *userdata, int fd, const void *buf, size_t count) {

    print_current_time("socket_write");

    struct WritePackage writePackage;
    writePackage.sockfd = fd;

    struct SyscallPackage syscallPackage;
    strcpy(syscallPackage.syscallId, "socket_write\0");
    syscallPackage.bufferedMessage = 1;
    syscallPackage.bufferedCount = count;
    syscallPackage.writePackage = writePackage;

    struct SyscallResponsePackage syscallResponse;

    int writePackageResult = write(data_socket, &syscallPackage, sizeof(struct SyscallPackage));

    if (writePackageResult == -1) {
        printf("Error writing WritePackage to socket...\n");
        return writePackageResult;
    }

    int writeBufferResult = write(data_socket, buf, count);

    if (writeBufferResult == -1) {
        printf("Error writing WriteBuffer to socket...\n");
        return writeBufferResult;
    }

    int numRead = read(data_socket, &syscallResponse, sizeof(struct SyscallResponsePackage));

    if (numRead == -1) {
        printf("Response not read from RTOS...\n");
        return -1;
    }

    printf("Response read from RTOS: %d...\n", syscallResponse.result);

    return syscallResponse.result;
}


static ssize_t freertos_sendto(void *userdata, int fd, const void *buf,
			  size_t count, int flags,
			  const struct sockaddr *dest_addr, socklen_t addrlen) {

    print_current_time("socket_sendto");

    struct SendToPackage sendToPackage;

    sendToPackage.sockfd = fd;
    sendToPackage.flags = flags;
    if (addrlen <= sizeof(struct sockaddr)) { // IPv4 has addr equal to sockaddr (16)
        memcpy(&sendToPackage.addr, dest_addr, addrlen);
    } else { // IPv6 has addr equal to 28
        memcpy(&sendToPackage.addr6, dest_addr, addrlen);
    }
    sendToPackage.addrlen = addrlen;

    struct SyscallPackage syscallPackage;
    strcpy(syscallPackage.syscallId, "socket_sendto\0");
    syscallPackage.bufferedMessage = 1;
    syscallPackage.bufferedCount = count;
    syscallPackage.sendToPackage = sendToPackage;

    struct SyscallResponsePackage syscallResponse;

    int sendToPackageResult = write(data_socket, &syscallPackage, sizeof(struct SyscallPackage));

    if (sendToPackageResult == -1) {
        printf("Error writing SendToPackage to socket...\n");
        return sendToPackageResult;
    }

    int writeBufferResult = write(data_socket, buf, count);

    if (writeBufferResult == -1) {
        printf("Error writing data to socket...\n");
        return writeBufferResult;
    }

    int numRead = read(data_socket, &syscallResponse, sizeof(struct SyscallResponsePackage));

    if (numRead == -1) {
        printf("Response not read from RTOS...\n");
        return -1;
    }

    printf("Response read from RTOS: %d...\n", syscallResponse.result);

    return syscallResponse.result;
}

static ssize_t freertos_read(void *userdata, int fd, void *buf, size_t count) {
    print_current_time("socket_read");
    struct ReadPackage readPackage;
    readPackage.sockfd = fd;
    readPackage.count = count;

    struct SyscallPackage syscallPackage;
    strcpy(syscallPackage.syscallId, "socket_read\0");
    syscallPackage.readPackage = readPackage;

    struct SyscallResponsePackage syscallResponse;

    int result = send_syscall(&syscallPackage, &syscallResponse);

    if (result == -1) {
        return -1;
    } else if (syscallResponse.result < 0) {
        return 0;
    } else {
        return syscallResponse.result;
    }
}

static ssize_t freertos_recvfrom(void *userdata, int sockfd, void *buf, size_t len,
			    int flags, struct sockaddr *src_addr,
			    socklen_t *addrlen) {
    print_current_time("socket_recvfrom");
    struct RecvFromPackage recvFromPackage;
    recvFromPackage.sockfd = sockfd;
    recvFromPackage.count = len;
    recvFromPackage.flags = flags;

    struct SyscallPackage syscallPackage;
    strcpy(syscallPackage.syscallId, "socket_recvfrom\0");
    syscallPackage.recvFromPackage = recvFromPackage;

    struct SyscallResponsePackage syscallResponse;

    int result = send_syscall(&syscallPackage, &syscallResponse);

    if (result == -1) {
        return -1;
    } else if (syscallResponse.result < 0) {
        return 0;
    } else {
        socklen_t socklen = syscallResponse.acceptResponse.addrlen;
        
        if (socklen == sizeof(struct sockaddr)) {
            memcpy(src_addr, &(syscallResponse.acceptResponse.addr), socklen);
        } else if (socklen == sizeof(struct sockaddr_in6)) {
            memcpy(src_addr, &(syscallResponse.acceptResponse.addr6), socklen);
        } else {
            // We assume that if this call was successful, the peer addr should have also been returned
            return -1;
        }
        
        *addrlen = syscallResponse.acceptResponse.addrlen;

        return syscallResponse.result;
    }
}

int freertos_usleep(void *userdata, useconds_t usec) {
    usleep(usec);
    return 0;
}

static void freertos_free(void *userdata) {

    print_current_time("socket_free");

    //printf("Sleeping for 10 seconds\n");

    //sleep(10);

    // int fclose_result = fclose(fp);

    // printf("fclose result: %d\n", fclose_result);

    int closeResult = close(data_socket);

    if (closeResult == 0) {
        printf("Closing data socket with close result: %d\n", closeResult);
    } else {
        printf("Closing data socket with close result: %d and errno: %d\n", closeResult, errno);
    }

    printf("Freeing up userdata...\n");

    free(userdata);

    printf("Freeing tun_fd");
    close(tun_fd);

}


int freertos_setsockopt(void *userdata, int sockfd, int level, int optname,
			  const void *optval, socklen_t optlen) {
    printf("freertos_setsockopt...\n");
    return 0;
}

int send_syscall(struct SyscallPackage *syscallPackage, struct SyscallResponsePackage *syscallResponse) {
    int ret = write(data_socket, syscallPackage, sizeof(struct SyscallPackage));

    if (ret == -1) {
        printf("Error writing to socket with error number: %s...\n", strerror(errno));
        return -1;
    } else {
        printf("Data printed to socket: %s...\n", syscallPackage->syscallId);
    }

    int numRead = read(data_socket, syscallResponse, sizeof(struct SyscallResponsePackage));

    if (numRead == -1) {
        printf("Response not read from RTOS...\n");
        return -1;
    }

    printf("Response read from RTOS: %d...\n", syscallResponse->result);

    return 0;
}



int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  /* Arguments taken by the function:
   *
   * char *dev: the name of an interface (or '\0'). MUST have enough
   *   space to hold the interface name if '\0' is passed
   * int flags: interface flags (eg, IFF_TUN etc.)
   */

   /* open the clone device */
   if( (fd = open(clonedev, O_RDWR)) < 0 ) {
        printf("tun open failed with code %d and errno %d...\n", fd, errno);
     return fd;
   }

   printf("Tap file descriptor is %d...\n", fd);

   /* preparation of the struct ifr, of type "struct ifreq" */
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

   if (*dev) {
     /* if a device name was specified, put it in the structure; otherwise,
      * the kernel will try to allocate the "next" device of the
      * specified type */
     strncpy(ifr.ifr_name, dev, IFNAMSIZ);
   }

   /* try to create the device */
   if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
        printf("tun ioctl failed with code %d and errno %s...\n", err, strerror(errno));
     close(fd);
     return err;
   }

  /* if the operation was successful, write back the name of the
   * interface to the variable "dev", so the caller can know
   * it. Note that the caller MUST reserve space in *dev (see calling
   * code below) */
  strcpy(dev, ifr.ifr_name);

  /* this is the special file descriptor that the caller will use to talk
   * with the virtual interface */
  return fd;
}

char *getSocketName() {
    char *socket_name;

    const char *interface_name = getenv("TAP_INTERFACE_NAME");

    if (interface_name != NULL) {
        
        int len = strlen(interface_name) + strlen("/tmp/socket-") + 1;
        socket_name = malloc(len * sizeof(char));
        snprintf(socket_name, len, "/tmp/socket-%s", interface_name);
    } else {
        socket_name = strdup("/tmp/socket-default");
    }

    return socket_name;
}


void packetdrill_interface_init(const char *flags, struct packetdrill_interface *interface) {

    // fp = fopen("/home/pamusuo/research/rtos-fuzzing/rtos-bridge/call-logs-data.txt", "w");

    print_current_time("rtos-bridge init time");

    interface->userdata = malloc(10 * sizeof(char));

    interface->write = freertos_write;
    interface->sendto = freertos_sendto;
    interface->read = freertos_read;
    interface->recvfrom = freertos_recvfrom;
    interface->socket = freertos_socket;
    interface->bind = freertos_bind;
    interface->listen = freertos_listen;
    interface->accept = freertos_accept;
    interface->connect = freertos_connect;
    interface->close = freertos_close;
    interface->setsockopt = freertos_setsockopt;
    interface->gettimeofday = freertos_gettimeofday;
    interface->netdev_send = freertos_netdev_send;
    interface->netdev_receive = freertos_netdev_receive;
    interface->usleep = freertos_usleep;
    interface->free = freertos_free;

    struct sockaddr_un peer_addr;

    int ret;

    data_socket = socket(AF_UNIX, SOCK_STREAM, 0);

    if (data_socket == -1) {
        printf("Error creating socket...\n");
        exit(EXIT_FAILURE);
    }

    char *remote_socket_name = getSocketName();

    memset(&peer_addr, 0, sizeof(struct sockaddr_un));

    peer_addr.sun_family = AF_UNIX;
    strcpy(peer_addr.sun_path, remote_socket_name);

    int connected = 0;

    while (!connected) {

        ret = connect(data_socket, (const struct sockaddr *) &peer_addr, sizeof(struct sockaddr_un));

        if (ret == 0) {
            //fprintf(stderr, "The server is down with error: %d...\n", ret);
            //exit(EXIT_FAILURE);

            connected = 1;
        
            printf("Connected to remote socket: V1.....\n");

            struct SyscallPackage syscallPackage;
            strcpy(syscallPackage.syscallId, "freertos_init\0");

            print_current_time("socket_init");

            struct SyscallResponsePackage syscallResponse;

            int result = send_syscall(&syscallPackage, &syscallResponse);

            print_current_time("socket_init_end");

            if (result == -1) {
                printf("Initializing FreeRTOS failed...\n");
            }
        } else {
            sleep(0.02);
        }
    }

    char tun_name[IFNAMSIZ];

    /* Connect to the device */
    char *interface_name;
    if ((interface_name = getenv("TAP_INTERFACE_NAME")) != NULL) {
        strcpy(tun_name, interface_name);
    } else if (strncmp(getenv("TAP_INTERFACE_NAME"), "tun", 3) != 0) {
        strcpy(tun_name, "tap1");
    } else {
        strcpy(tun_name, "tun0");
    }
    

    if (getenv("PD_TAP_FD")) {
        printf("TAP_FD found in environment... using...\n");
        tun_fd = atoi(getenv("PD_TAP_FD"));
    } else {
        printf("TAP_FD not found in environment... generating...\n");
        int interface_flag = (strncmp(getenv("TAP_INTERFACE_NAME"), "tun", 3) != 0) ? IFF_TAP : IFF_TUN;
        tun_fd = tun_alloc(tun_name, interface_flag | IFF_NO_PI);  /* tun interface */
    }

    

    if(tun_fd < 0){
        printf("Allocating interface failed with code: %d and errno: %d...\n", tun_fd, errno);
        exit(-1);
    }

}

/* void print_current_time(char *message) {
    struct timeval te;

    gettimeofday(&te, NULL);

    double milliseconds = te.tv_sec * 1000LL + te.tv_usec/1000;

    printf("%s: ", message);
    printf("%f\n", milliseconds);

} */

void print_current_time(char *message) {
    /* time_t timer;
    char buffer[26];
    int millisec;
    struct tm *tm_info;

    struct timeval tv;
    gettimeofday(&tv, NULL);

    timer = time(NULL);
    tm_info = localtime(&timer);

    millisec = tv.tv_usec/1000.0;

    fprintf(fp, "%s: ", message);
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(fp, "%s.%03d\n", buffer, millisec); */

}
