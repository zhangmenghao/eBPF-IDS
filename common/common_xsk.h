/* This common_xsk.h is used by userspace programs */
#ifndef _COMMON_XSK_H
#define _COMMON_XSK_H

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct stats_record {
	uint64_t timestamp;
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	uint32_t outstanding_tx;

	struct stats_record stats;
	struct stats_record prev_stats;
};

typedef bool (*xsk_pkt_func)(struct xsk_socket_info*, uint64_t, uint32_t);

uint64_t xsk_gettime(void);
void stats_print(struct stats_record *, struct stats_record *);
void handle_receive_packets(struct xsk_socket_info *, xsk_pkt_func);
int af_xdp_init(struct config *, int,
				struct xsk_umem_info **, struct xsk_socket_info **);

#endif
