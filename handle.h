enum handle_state {
	HANDLE_AVAILABLE,
	HANDLE_READY,
	HANDLE_RECEIVING,
	HANDLE_CLOSING,
};

struct handle {
	enum handle_state state;
	int fd;
};

struct handle_list {
	int n;
	struct handle *fds;
};

void handle_module_init(void *(*mem_alloc_p)(const size_t),
		void (*mem_free_p)(void *));

int handle_list_init(struct handle_list *fdl, int n);

void handle_list_free(struct handle_list *fdl);

struct handle *handle_list_get_by_state(struct handle_list *fdl,
		enum handle_state state);

struct handle *handle_list_get_by_fd(struct handle_list *fdl, int fd);
