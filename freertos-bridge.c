#include "freertos-bridge.h"
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

//gcc -c -Wall -Werror -fPIC freertos-bridge.c
//gcc -shared -o libfreertos-bridge.so freertos-bridge.o

#define REMOTE_SOCKET_NAME "/tmp/mysocket1"
#define CLIENT_SOCKET_NAME "/tmp/clientsocket2"
#define BUFFER_SIZE 20
#define ETH_IP_TYPE        0x0800
#define FUZZ_MODE 1
// 1 - CVE-2018-16524
// 2 - CVE-2018-16601
// 3 - CVE-2018-16603
// 4 - CVE-2018-16526

static int data_socket;
static int tun_fd;

struct AcceptPackage {
    int sockfd;
};

struct BindPackage {
    int sockfd;
    struct sockaddr addr;
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

struct ReadPackage {
    int sockfd;
    size_t count;
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
        struct BindPackage bindPackage;
        struct ListenPackage listenPackage;
        struct AcceptPackage acceptPackage;
        struct BindPackage connectPackage;
        struct WritePackage writePackage;
        struct ClosePackage closePackage;
        struct ReadPackage readPackage;
    };
};

struct AcceptResponsePackage {
    struct sockaddr addr;
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
    printf("Creating a freertos socket\n");

    struct SyscallPackage syscallPackage;
    strcpy(syscallPackage.syscallId, "socket_create\0");


    struct SyscallResponsePackage syscallResponse;

    int result = send_syscall(&syscallPackage, &syscallResponse);

    if (result == -1) {
        return 0;
    }

    return syscallResponse.result;
}

static int freertos_bind (void *userdata, int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

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

    struct AcceptPackage acceptPackage;

    acceptPackage.sockfd = sockfd;

    struct SyscallPackage syscallPackage;
    strcpy(syscallPackage.syscallId, "socket_accept\0");
    syscallPackage.acceptPackage = acceptPackage;

    struct SyscallResponsePackage syscallResponse;

    int result = send_syscall(&syscallPackage, &syscallResponse);

    if (result == -1) {
        return 0;
    }

    memcpy(addr, &(syscallResponse.acceptResponse.addr), sizeof(struct sockaddr));
    *addrlen = syscallResponse.acceptResponse.addrlen;

    return syscallResponse.result;
}


static int freertos_connect (void *userdata, int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

    struct BindPackage connectPackage;

    connectPackage.sockfd = sockfd;
    memcpy(&connectPackage.addr, addr, sizeof(struct sockaddr));
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

    printf("IP packet to be sent:\n");
    print_hex((unsigned char *)buf, count);
    printf("\n");
//46:e7:d7:aa:9b:5f
    struct EthernetHeader ethernetHeader;
    uint8_t destinationAddress[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x41};
    //uint8_t sourceAddress[6] = {0x3A, 0x01, 0x49, 0xBA, 0x4C, 0xCE};
    uint8_t sourceAddress[6] = {0x46, 0xE7, 0xD7, 0xAA, 0x9B, 0x5F};

    memcpy(ethernetHeader.destinationAddress, destinationAddress, sizeof(destinationAddress));
    memcpy(ethernetHeader.sourceAddress, sourceAddress, sizeof(sourceAddress));
    ethernetHeader.frameType = htons(ETH_IP_TYPE);

    size_t ethernetHeaderSize = sizeof(struct EthernetHeader);

    size_t ethernetFrameSize = count + ethernetHeaderSize;

    char *ethernetFrame = malloc(ethernetFrameSize);

    memcpy(ethernetFrame, &ethernetHeader, ethernetHeaderSize);
    memcpy(ethernetFrame + ethernetHeaderSize, buf, count);

    printf("Correct Ethernet frame:\n");
    print_hex((unsigned char *)ethernetFrame, ethernetFrameSize);

    if (ethernetFrameSize == 66 && FUZZ_MODE == 1) {
        ethernetFrame[17] = 0x29;
        ethernetFrameSize -= 11;
    } else if (ethernetFrameSize == 66 && FUZZ_MODE == 2) {
        ethernetFrame[14] = 0x4F;
    } else if (ethernetFrameSize == 66 && FUZZ_MODE == 3) {
        ethernetFrame[17] = 0x14;
        ethernetFrameSize -= 32;
    } else if (ethernetFrameSize == 2054 && FUZZ_MODE == 4) {
        ethernetFrameSize += 8;
        ethernetFrame = realloc(ethernetFrame, ethernetFrameSize);
        char *frameOffset = ethernetFrame + 34;
        memmove(frameOffset + 8, frameOffset, ethernetFrameSize - 42);
        memset(frameOffset, 0, 8);
        ethernetFrame[14] = 0x47;

    }

    ssize_t ret = write(tun_fd, ethernetFrame, ethernetFrameSize);

    printf("Ethernet frame sent\n");
    print_hex((unsigned char *)ethernetFrame, ethernetFrameSize);

    /*printf("Ethernet frame sent:\n");
    print_hex((unsigned char *)ethernetFrame, ethernetFrameSize);
    printf("Ethernet frame with offset of 5\n");
    print_hex((unsigned char *)ethernetFrame, ethernetFrameSize - 10);*/
    printf("\n");

    if (ret < 0) {
        printf("An error occurred sending ethernet frame...\n");
        return -1;
    } else if (ret != ethernetFrameSize) {
        printf("Incorrect ethernet frame size sent: %lu bytes...\n", ret);
        return -1;
    } else {
        printf("Ethernet frame successfully sent: %lu bytes...\n", ret);
        return 0;
    }

}

static int freertos_netdev_receive (void *userdata, void *buffer, size_t *count,
			      long long *time_usecs) {

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

        if (memcmp(tempBuffer, hostAddress, 6) == 0 && memcmp(tempBuffer + 6, sutAddress, 6) == 0) {
            printf("Found outbound frame\n");
            print_hex((unsigned char *)tempBuffer, numRead);
            printf("\n");

        } else {
            printf("Not outbound frame\n");
            print_hex((unsigned char *)tempBuffer, numRead);
            printf("\n");
            free(tempBuffer);
            continue;
        }

        memcpy(buffer, tempBuffer + ethernetHeaderSize, numRead - ethernetHeaderSize);
        *count = numRead - ethernetHeaderSize;

        struct timeval tv;
        gettimeofday(&tv, NULL);
        *time_usecs = 1000000 * (uint64_t)tv.tv_sec + tv.tv_usec;

        free(tempBuffer);

        return 0;

    }

}


static ssize_t freertos_write(void *userdata, int fd, const void *buf, size_t count) {

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

static ssize_t freertos_read(void *userdata, int fd, void *buf, size_t count) {
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

int freertos_usleep(void *userdata, useconds_t usec) {
    usleep(usec);
    return 0;
}

static void freertos_free(void *userdata) {

    /*printf("freertos_free called...\n");
    struct SyscallPackage syscallPackage;
    strcpy(syscallPackage.syscallId, "socket_free\0");

    struct SyscallResponsePackage syscallResponse;

    int result = send_syscall(&syscallPackage, &syscallResponse);

    if (result == -1) {
        printf("Freeing FreeRTOS failed...\n");
    }*/

    int closeResult = close(data_socket);

    printf("Closing data socket with close result: %d and errno: %d\n", closeResult, errno);

    printf("Freeing up userdata...\n");

    free(userdata);

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
     return fd;
   }

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


void packetdrill_interface_init(const char *flags, struct packetdrill_interface *interface) {

    interface->userdata = malloc(10 * sizeof(char));

    interface->write = freertos_write;
    interface->read = freertos_read;
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

    struct sockaddr_un my_addr, peer_addr;

    int ret;

    data_socket = socket(AF_UNIX, SOCK_STREAM, 0);

    if (data_socket == -1) {
        printf("Error creating socket...\n");
        exit(EXIT_FAILURE);
    }

    //int reuse = 1;

    /*if (setsockopt(data_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        printf("setsockopt(SO_REUSEADDR) failed...\n");
    }

    if (setsockopt(data_socket, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)) < 0) {
        printf("setsockopt(SO_REUSEPORT) failed");
    }*/

    /*struct linger lin;
    lin.l_onoff = 0;
    lin.l_linger = 0;
    setsockopt(data_socket, SOL_SOCKET, SO_LINGER, (const char *)&lin, sizeof(int));*/

    memset(&my_addr, 0, sizeof(struct sockaddr_un));
    memset(&peer_addr, 0, sizeof(struct sockaddr_un));

    my_addr.sun_family = AF_UNIX;
    strcpy(my_addr.sun_path, CLIENT_SOCKET_NAME);

    peer_addr.sun_family = AF_UNIX;
    strcpy(peer_addr.sun_path, REMOTE_SOCKET_NAME);

    ret = connect(data_socket, (const struct sockaddr *) &peer_addr, sizeof(struct sockaddr_un));

    if (ret != 0) {
        fprintf(stderr, "The server is down with error: %d...\n", ret);
        exit(EXIT_FAILURE);
    } else {
        printf("Connected to remote socket: V1.....\n");

        struct SyscallPackage syscallPackage;
        strcpy(syscallPackage.syscallId, "freertos_init\0");

        struct SyscallResponsePackage syscallResponse;

        int result = send_syscall(&syscallPackage, &syscallResponse);

        if (result == -1) {
            printf("Initializing FreeRTOS failed...\n");
        }
    }

    char tun_name[IFNAMSIZ];

    /* Connect to the device */
    strcpy(tun_name, "tap0");
    tun_fd = tun_alloc(tun_name, IFF_TAP | IFF_NO_PI);  /* tun interface */

    if(tun_fd < 0){
        printf("Allocating interface failed with code: %d and errno: %d...\n", tun_fd, errno);
        exit(-1);
    }

}

/*!
 * @brief print binary packet in hex
 * @param [in] bin_daa data to print
 * @param [in] len length of the data
 */
/*
static void print_hex( unsigned char * bin_data,
                       size_t len )
*/
/*static void print_hex(unsigned char *bin_data, size_t len) *//*

{
    size_t i;

    for( i = 0; i < len; ++i )
    {
        printf( "%.2X ", bin_data[ i ] );
    }

    printf( "\n" );
}*/
