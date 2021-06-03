#include "request.h"
#include "server_thread.h"
#include "common.h"

struct server {
	int nr_threads;
	int max_requests;
	int max_cache_size;
	int exiting;
	/* add any other parameters you need */
};

struct bucket {
	struct file_data *file_info;
	int use_count;
	struct bucket *next;
};

struct cache {
	int size;
	int max_cache_size;
	int curr_mem;
	struct bucket **table;
};

struct buffer_queue{
	int connfd;
	struct buffer_queue* next;	
};

struct buffer_queue_head{
	int count;
	struct buffer_queue* head;
};

struct eviction_queue{
	char *file_name;
	struct eviction_queue *next;	
};

struct eviction_queue_head{
	struct eviction_queue *head;
       	struct eviction_queue *last_node;
};

struct buffer_queue_head* bq;
pthread_t* thread_id;

struct cache* ch;
struct eviction_queue_head* eq;

pthread_mutex_t lock_buffer;
pthread_mutex_t lock_exit;
pthread_mutex_t lock_cache;
pthread_mutex_t lock_eq;

pthread_cond_t buffer_full;
pthread_cond_t buffer_empty; 


/* static functions */

/* initialize file data */
static struct file_data *
file_data_init(void)
{
	struct file_data *data;

	data = Malloc(sizeof(struct file_data));
	data->file_name = NULL;
	data->file_buf = NULL;
	data->file_size = 0;
	return data;
}

/* free all file data */
static void
file_data_free(struct file_data *data)
{
	free(data->file_name);
	free(data->file_buf);
	free(data);
}

// Hashmap functions

// Initialize hashmap
void
init_hash_map(long size, int max_cache_size)
{
	// If size > 0, initalize table values
	if(size > 0){
		ch->table = (struct bucket**)malloc(sizeof(struct bucket *) * size);
	       	assert(ch->table);
		
		// Initialize elements of hashmap	
		for(long i = 0; i < size; i++) ch->table[i] = NULL;

		ch->max_cache_size = max_cache_size;
	} else {
		ch->table = NULL;
		ch->max_cache_size = 0;
	}
	
	ch->size = size;
	ch->curr_mem = 0;
}

void
destroy_hash_map()
{
	struct bucket *curr;
	struct bucket *temp;

	if(ch->table != NULL){
		for(long i = 0; i < ch->size; i++){
			curr = ch->table[i];
			while(curr != NULL){
				temp = curr;
				curr = curr->next;
				file_data_free(temp->file_info);
				free(temp);
			}
		}
	}

	free(ch->table);
	free(ch);
}

struct eviction_queue*
new_eq(char *file_name)
{
	struct eviction_queue *new_node = (struct eviction_queue*)malloc(sizeof(struct eviction_queue));
	
	new_node->file_name = file_name;
	new_node->next = NULL;
		
	return new_node;
}

void
insert_eq_node(struct eviction_queue *new_node)
{
	if(eq->head == NULL){
		eq->head = new_node;
		eq->last_node = new_node;
	} else {
		eq->last_node->next = new_node;
		eq->last_node = new_node;	
	}
}

void
send_to_back(char *file_name)
{
	struct eviction_queue *curr = eq->head;
	struct eviction_queue *temp;
	
	// if node is already at the end	
	if(strcmp(eq->last_node->file_name,file_name) == 0) return;
	
	// if node is at the front
	if(strcmp(eq->head->file_name,file_name) == 0){
		temp = eq->head;
		eq->head = temp->next;
		temp->next = NULL;
		eq->last_node->next = temp;
		eq->last_node = temp;
		
		return;
	}	
	
	// if node is somewhere in the middle	
	while(curr != NULL && curr->next != NULL && 
			strcmp(curr->next->file_name,file_name) != 0)
	{
		curr = curr->next;
	}
	
	if(curr != NULL && curr->next != NULL && 
			strcmp(curr->next->file_name,file_name) == 0){
		temp = curr->next;
	       	curr->next = temp->next;
		temp->next = NULL;
		eq->last_node->next = temp;
		eq->last_node = temp;	
	}
}


unsigned int
hash(char *file_name)
{
	unsigned long hash_val = 5381;
       	int c;

	while((c = *file_name++)) 
		hash_val = ((hash_val << 5) + hash_val) + c;
	
	return hash_val % ch->size;	
}

struct bucket*
cache_find_file(char *file_name, unsigned int hash_val)
{
	struct bucket *file_location = ch->table[hash_val];

	while(file_location != NULL){
		if (strcmp(file_name,file_location->file_info->file_name) == 0)
		       return file_location;
		file_location = file_location->next;
	}
	
	return NULL;
}

void 
remove_from_list(char *file_name)
{
	struct eviction_queue *curr = eq->head;
	struct eviction_queue *temp; 
	
	if(eq->head != NULL){
		// at the front	
		// only 1 node
		if(strcmp(eq->head->file_name,file_name) == 0 && 
				strcmp(eq->last_node->file_name,file_name) == 0)
		{
			temp = eq->head;
			eq->head = NULL;
			eq->last_node = NULL;
			free(temp);
			return;
		}
		
		// at the front
		// more than 1 node
		else if(strcmp(eq->head->file_name,file_name) == 0){
			temp = eq->head;
			eq->head = temp->next;
			free(temp);
			return;
		
		}

		else{
			while(curr != NULL && curr->next != NULL &&
					strcmp(curr->next->file_name,file_name) != 0)
			{
				curr = curr->next;
			}

			// Node at the end
			if(strcmp(eq->last_node->file_name,file_name) == 0){
				temp = curr->next;
				curr->next = temp->next;	
				free(temp);
				eq->last_node = curr;
				return;
			}

			// Node in the middle
			if(curr != NULL && curr->next != NULL &&
					strcmp(curr->next->file_name,file_name) == 0)
			{
				temp = curr->next;
				curr->next = temp->next;
				free(temp);
				return;
			}
		}
	}
}

void
remove_bucket(char *file_name, unsigned int hash_val)
{
	
	struct bucket *file_location = ch->table[hash_val];
	struct bucket *temp;

	if(file_location != NULL && 
			strcmp(file_location->file_info->file_name,file_name) == 0){
		ch->table[hash_val] = file_location->next;
		file_data_free(file_location->file_info);
		free(file_location);
		return;
	}

	while(file_location != NULL && file_location != NULL && 
			strcmp(file_location->next->file_info->file_name,file_name) != 0){
		file_location = file_location->next;
	}

	if(file_location != NULL && file_location != NULL && 
			strcmp(file_location->next->file_info->file_name,file_name) == 0){
		temp = file_location->next;
		file_location->next = temp->next;
		file_data_free(temp->file_info);
		free(temp);		
	}
		
}

int 
get_first_eq_node()
{	
	struct eviction_queue *curr = eq->head;
	struct bucket *file_location;
	unsigned int hash_val;
	char *file_name;

	if(eq->head != NULL){
		while(curr != NULL){
			hash_val = hash(curr->file_name);
			file_location = cache_find_file(curr->file_name,hash_val);	
			if(file_location->use_count == 0){
				file_name = curr->file_name;
				remove_from_list(file_name);
				ch->curr_mem -= file_location->file_info->file_size;
				remove_bucket(file_name,hash_val);	
				return 1;		
			} else {
				curr = curr->next;
			}	
		}
	}

	return 0;
}

void
reduce_use_count(char *file_name)
{
	assert(file_name);
	pthread_mutex_lock(&lock_cache);
	unsigned int hash_val = hash(file_name);
	struct bucket *file_location = cache_find_file(file_name,hash_val);
	
	if(file_location != NULL && file_location->use_count > 0) file_location->use_count--;
	
	pthread_mutex_unlock(&lock_cache);
}

void
cache_evict(int space_required)
{
	if(space_required > ch->max_cache_size) return; 
	int ret = 1;

	pthread_mutex_lock(&lock_eq);
	while(space_required > ch->max_cache_size - ch->curr_mem && ret == 1){
		ret = get_first_eq_node();				
	}
	pthread_mutex_unlock(&lock_eq);
}

struct file_data*
cache_lookup(char *file_name)
{
	pthread_mutex_lock(&lock_cache);
	unsigned int hash_val = hash(file_name);
	struct bucket *file_location = cache_find_file(file_name,hash_val);
	
	if(file_location != NULL){
		file_location->use_count++;
		pthread_mutex_unlock(&lock_cache);
		
		pthread_mutex_lock(&lock_eq);
		send_to_back(file_name);
		pthread_mutex_unlock(&lock_eq);

		return file_location->file_info;
	}		
	
	pthread_mutex_unlock(&lock_cache);
	return NULL;	
}

void
cache_insert(struct file_data *file_info)
{
	pthread_mutex_lock(&lock_cache);
	unsigned int hash_val = hash(file_info->file_name);
	struct bucket *file_location = cache_find_file(file_info->file_name, hash_val);
	
	if(file_location == NULL){
		if(file_info->file_size + ch->curr_mem >= ch->max_cache_size){
			cache_evict((file_info->file_size + ch->curr_mem) - ch->max_cache_size); 	
		}	
		if(file_info->file_size + ch->curr_mem <= ch->max_cache_size){
			struct bucket *new_file = (struct bucket*)malloc(sizeof(struct bucket));
			assert(new_file);
			ch->curr_mem += file_info->file_size;
			new_file->use_count = 1;
			new_file->file_info = file_info;
			new_file->next = ch->table[hash_val];
			ch->table[hash_val] = new_file;
			pthread_mutex_unlock(&lock_cache);

			struct eviction_queue *new_eq_node = new_eq(file_info->file_name);
		       	pthread_mutex_lock(&lock_eq);
			insert_eq_node(new_eq_node);	
			pthread_mutex_unlock(&lock_eq);

			return;
		}
	}

	pthread_mutex_unlock(&lock_cache);	
}

static void
do_server_request(struct server *sv, int connfd)
{
	int ret;
	struct request *rq;
	struct file_data *data;

	data = file_data_init();

	/* fill data->file_name with name of the file being requested */
	rq = request_init(connfd, data);
	if (!rq) {
		file_data_free(data);
		return;
	}
	
	if(ch->size > 0){
		struct file_data *file_info = cache_lookup(data->file_name);
		if(file_info != NULL){
			request_set_data(rq,file_info);
		} else {
			/* read file, 
			 * fills data->file_buf with the file contents,
			 * data->file_size with file size. */
			ret = request_readfile(rq);
			if (ret == 0) { /* couldn't read file */
				goto out;
			} else {
				cache_insert(data);
			}
			
		}
		
		/* send file to client */
		request_sendfile(rq);
		reduce_use_count(data->file_name);
	
	} else {
		/* read file, 
		 * fills data->file_buf with the file contents,
		 * data->file_size with file size. */
		ret = request_readfile(rq);
		if (ret == 0) { /* couldn't read file */
			goto out;
		}
		/* send file to client */
		request_sendfile(rq);
	}

out:
	request_destroy(rq);
	if(ch->size == 0){
		file_data_free(data);
	}
}

void
destroy_buffer()
{
	struct buffer_queue* temp = bq->head;
	while(temp != NULL){
		bq->head = bq->head->next;
		free(temp);
		temp = bq->head;
	}
	free(bq);
}

void 
push(int connfd)
{
	struct buffer_queue *curr = bq->head;
	struct buffer_queue *new_slot = malloc(sizeof(struct buffer_queue));
	new_slot->connfd = connfd;
	new_slot->next = NULL;

	if(curr == NULL){
		bq->head = new_slot;
	} else {
		while(curr->next != NULL) curr = curr->next;
		curr->next = new_slot;
	}
}	

int 
pop()
{
	int connfd;

	struct buffer_queue* temp;
	connfd = bq->head->connfd;
	temp = bq->head;
	bq->head = bq->head->next;
	free(temp);	

	return connfd;
}

void*
do_multi_thread_server_request(void *arg)
{
	struct server* sv = (struct server*)arg;
	while(!sv->exiting){
		pthread_mutex_lock(&lock_buffer);
		while(bq->count == 0) {
			// exit worker thread if server is exiting 
			if(sv->exiting) {
				pthread_mutex_unlock(&lock_buffer);
				return 0;
			}
			// Wait while buffer is empty
			pthread_cond_wait(&buffer_empty,&lock_buffer);
		}
		int connfd = pop();
		if(sv->max_requests == bq->count) pthread_cond_signal(&buffer_full);
	       	bq->count -= 1;	
		pthread_mutex_unlock(&lock_buffer);		
		do_server_request(sv,connfd);	
	}	
	return 0;
}

/* entry point functions */

struct server *
server_init(int nr_threads, int max_requests, int max_cache_size)
{
	struct server *sv;

	sv = Malloc(sizeof(struct server));
	sv->nr_threads = nr_threads;
	sv->max_requests = max_requests;
	sv->max_cache_size = max_cache_size;
	sv->exiting = 0;
	
	if (nr_threads > 0 || max_requests > 0 || max_cache_size > 0) {
		
		/* Lab 4: create queue of max_request size when max_requests > 0 */
		bq = malloc(sizeof(struct buffer_queue_head));
		bq->count = 0;
		bq->head = NULL;	
		
		pthread_mutex_init(&lock_buffer,NULL);
		pthread_mutex_init(&lock_exit,NULL);	
		pthread_mutex_init(&lock_cache,NULL);
		pthread_mutex_init(&lock_eq,NULL);	
		pthread_cond_init(&buffer_full,NULL);
		pthread_cond_init(&buffer_empty,NULL); 	

		/* Lab 4: create worker threads when nr_threads > 0 */
		thread_id = malloc(sizeof(pthread_t) * nr_threads);
		for(int i = 0; i < nr_threads; i++){
			pthread_create(&thread_id[i],NULL,do_multi_thread_server_request,sv);
		}
		
		/* Lab 5: init server cache and limit its size to max_cache_size */
		long size = ceil(max_cache_size/12000) * 2;
		ch = (struct cache*)malloc(sizeof(struct cache));
		init_hash_map(size, max_cache_size);
	       	
		/* Lab 5: EQ */
		eq = malloc(sizeof(struct eviction_queue_head));
		eq->head = NULL;	
		eq->last_node = NULL;
	}

	return sv;
}

void
server_request(struct server *sv, int connfd)
{
	if (sv->nr_threads == 0) { /* no worker threads */
		do_server_request(sv, connfd);
	} else {
		/*  Save the relevant info in a buffer and have one of the
		 *  worker threads do the work. */
		pthread_mutex_lock(&lock_buffer);
		while(sv->max_requests == bq->count){
			// If max number of requests are in queue
			// wait for space
			pthread_cond_wait(&buffer_full,&lock_buffer);
		}
		push(connfd);			
		// If buffer is empty, wake up any worker thread
		// And increment worker count
		if(bq->count == 0) pthread_cond_broadcast(&buffer_empty); 
		bq->count += 1;
		pthread_mutex_unlock(&lock_buffer);
	}
}

void
server_exit(struct server *sv)
{
	/* when using one or more worker threads, use sv->exiting to indicate to
	 * these threads that the server is exiting. make sure to call
	 * pthread_join in this function so that the main server thread waits
	 * for all the worker threads to exit before exiting. */
	sv->exiting = 1;
	
	// wake up all threads
	pthread_mutex_lock(&lock_buffer);
	pthread_cond_broadcast(&buffer_empty);
	pthread_mutex_unlock(&lock_buffer);	

	for(int i = 0; i < sv->nr_threads; i++){
		pthread_join(thread_id[i],NULL);	
	}

	/* make sure to free any allocated resources */
	destroy_buffer();
	free(thread_id);
	
	free(sv);
}
