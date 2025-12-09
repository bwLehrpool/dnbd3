#ifdef DNBD3_SERVER_AFL
#define send(a,b,c,d) write((a) == 0 ? 1 : (a), b, c)
#define recv(a,b,c,d) read(a, b, c)
#endif
