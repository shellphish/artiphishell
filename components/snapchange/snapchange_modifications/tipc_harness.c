#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <linux/netlink.h>

// globals

// variables used for the connecting socket.
int g_sockfd = -1;
struct sockaddr_in g_sockaddr;

int setup_socket(uint32_t domain, uint32_t type, uint32_t protocol, uint16_t port )
{
    printf("[INFO] Opening socket with Domain: %d Type: %d Protocol: %d Port: %d\n",
        domain, type, protocol, port);

    if ((g_sockfd = socket(domain, type, protocol)) < 0) {
        g_sockfd = -1;
        return -1;
    }

    memset((char *) &g_sockaddr, 0, sizeof(g_sockaddr));
    g_sockaddr.sin_family = domain;
    g_sockaddr.sin_port = htons(port);

    if (inet_aton("127.0.0.1", &g_sockaddr.sin_addr) == 0) {
        close(g_sockfd);
        g_sockfd = -1;

        return -1;
    }
    

    return 0;
}

int send_data(uint8_t *buf, uint32_t flags, uint32_t sz)
{
    printf("[INFO] Sending data flags: %x size: %x\n", flags, sz);

    return sendto( g_sockfd, buf, sz, flags, (struct sockaddr*)&g_sockaddr, sizeof(g_sockaddr) );
}

// netlink
int netlink_send( uint16_t type, uint16_t flags, uint32_t protocol, uint32_t seq, uint8_t* pkt, size_t pkt_len) 
{
    int sock_fd;
    struct sockaddr_nl sa;
    struct msghdr m;
    size_t nread;

    printf("[INFO] Sending netlink type: %x flags: %x prot: %x seq %x pktlen: %lx\n", type, flags, protocol, seq, pkt_len);

    memset(&m, 0, sizeof(struct msghdr));
    memset(&sa, 0, sizeof(struct sockaddr_nl));
    sa.nl_family = AF_NETLINK;

    size_t pkt_full_len = sizeof(struct nlmsghdr) + pkt_len;
    uint8_t *pkt_full = malloc(pkt_full_len);
    memset(pkt_full, 0, pkt_full_len); 
    memcpy(pkt_full + sizeof(struct nlmsghdr), pkt, pkt_len);

    struct nlmsghdr *netlink_hdr = (struct nlmsghdr*)(pkt_full);
    netlink_hdr->nlmsg_len = pkt_full_len;
    netlink_hdr->nlmsg_type = type;
    netlink_hdr->nlmsg_flags = flags;
    netlink_hdr->nlmsg_seq = seq;
    netlink_hdr->nlmsg_pid = getpid();

    if ((sock_fd = socket(PF_NETLINK, SOCK_RAW, protocol)) < 0) {
        perror("socket");
        return -1;
    }

    if (bind(sock_fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("bind");
        return -1;
    }

    ssize_t r = sendto(
        sock_fd, pkt_full, pkt_full_len, 0, 
        (struct sockaddr*)&sa, sizeof(struct sockaddr_nl)
    );

    if (r < 0) {
        perror("sendto");
        return -1;
    }

    free(pkt_full);

    // Eat the response but do nothing with it for now.
    m.msg_iovlen = 1;
    m.msg_iov = malloc(sizeof(struct iovec));
    m.msg_iov->iov_base = malloc(0x1000);
    m.msg_iov->iov_len = 0x1000;

    if ((nread = recvmsg(sock_fd, &m, 0)) < 0) {
        goto error;
    }

    free(m.msg_iov->iov_base);

    close(sock_fd);
    return 0;

error:
    close(sock_fd);
    return -1;
}

/*
 * Expects a blob in the format of:
 * Protocol examples, NETLINK_GENERIC, NETLINK_ROUTE
 * [4-bytes Message Type][4-bytes Message Flags][4-bytes Netlink Protocol][4-bytes size][size bytes data]
 * [4-bytes Message Type][4-bytes Message Flags][4-bytes Netlink Protocol][4-bytes size][size bytes data]
 * ....
 * Returns -1 on a failure, the size consumed
 */
int send_netlink_packet( uint8_t *blob, uint32_t blob_size)
{
    int index = 0;
    uint32_t packet_size = 0;
    uint32_t msg_type;
    uint32_t msg_flags;
    uint32_t protocol;

    if ( blob == NULL ) {
        return -1;
    }

    if ( blob_size < 16 ) {
        return -1;
    }

    memcpy(&msg_type, blob, 4);
    memcpy(&msg_flags, blob + 4, 4);
    memcpy(&protocol, blob + 8, 4);
    memcpy(&packet_size, blob + 12, 4);

    index += 16;

    if ( blob_size - index < packet_size ) {
        return -1;
    }
    
    if ( netlink_send( msg_type, msg_flags, protocol, time(NULL), blob + index, packet_size) < 0 ) {
        return -1;
    }

    index += packet_size;

    sleep(2);

    return index;
}

/***
 * Blob begins with a 4 byte command count
 * [4-bytes command count]
 * Currently there are two commands:
 *  0 - send a packet blob
 *      [4-bytes size][4-bytes send flags][size-bytes packet data]
 *  1 - send a netlink packet
 *      [4-bytes Message Type][4-bytes Message Flags][4-bytes Netlink Protocol][4-bytes size][size bytes data]
 * blob_size MUST be a trusted value
 */
int harness( uint8_t *blob, uint32_t blob_size)
{
    int index = 0;
    uint32_t command, command_count = 0;
    uint32_t flags, packet_size = 0;
    uint32_t domain, type, protocol;
    uint16_t port;
    int res;

    uint32_t level, optname, optval;

    if ( blob == NULL ) {
        return -1;
    }

    // Enable the socket
    if ( setup_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 6118) < 0 ) {
        return -1;
    }

    
    // A blob will at least be 4 bytes even if no packets are sent
    if ( blob_size < 4 ) {
        return -1;
    }

    memcpy(&command_count, blob, 4);
    index += 4;

    printf("[INFO] Executing %d commands\n", command_count);

    for ( int i = 0; i < command_count; i++) {
        if ( blob_size - index < 4 ) {
            return -1;
        }

        memcpy(&command, blob + index, 4);
        index += 4;

        switch ( command ) {
        case 0:
            if ( blob_size - index < 8 ) {
                close(g_sockfd);
                return -1;
            }

            memcpy(&packet_size, blob + index, 4);
            memcpy(&flags, blob + index + 4, 4);
            index += 8;

            if ( blob_size - index < packet_size ) {
                close(g_sockfd);
                return -1;
            }

            if ( send_data( blob + index, flags, packet_size ) < 0) {
                close(g_sockfd);
                return -1;
            } 

            index += packet_size;
            break;
        case 1:
            res = send_netlink_packet( blob + index, blob_size - index);

            if ( res < 0 ) {
                printf("send_netlink_packet() error\n");
                return -1;
            }

            index += res;

            break;
        default:
            printf("[ERROR] Unknown command: %x\n", command);
            return -1;

        };
    }

    printf("[INFO] Sending completed\n");
    close(g_sockfd);
    return -1;
}

int main(int argc, char *argv[])
{
    char *blob = NULL;
    struct stat st;
    int fd;

    if (argc < 2) {
        printf("Need file\n");
        return -1;
    }

    if ( stat(argv[1], &st) != 0) {
        printf("Failed to stat file\n");
        return -1;
    }

    fd = open(argv[1], O_RDONLY);

    if ( fd < 0 ) {
        printf("[ERROR] Failed to open file\n");
        return -1;
    }

    blob = malloc(st.st_size);

    if ( blob == NULL ) {
        return 0;
    }

    read(fd, blob, st.st_size);

    close(fd);

    harness(blob, st.st_size);

    return 0;
}
