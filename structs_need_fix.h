// #include <cstdint>
#define __SOCKADDR_COMMON_SIZE (sizeof(unsigned short int))
typedef uint32_t in_addr_t;

#define __SOCKADDR_COMMON(sa_prefix) sa_family_t sa_prefix##family

typedef unsigned short int sa_family_t;
struct in_addr {
  in_addr_t s_addr;
};

typedef uint16_t in_port_t;

struct sockaddr {
  __SOCKADDR_COMMON(sa_); /* Common data: address family and length.  */
  char sa_data[14];       /* Address data.  */
};

struct sockaddr_in {
  __SOCKADDR_COMMON(sin_);
  in_port_t sin_port;      /* Port number.  */
  struct in_addr sin_addr; /* Internet address.  */

  /* Pad to size of `struct sockaddr'.  */
  unsigned char sin_zero[sizeof(struct sockaddr) - __SOCKADDR_COMMON_SIZE -
                         sizeof(in_port_t) - sizeof(struct in_addr)];
};
