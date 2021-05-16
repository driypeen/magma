 #include <stdio.h>
#include </usr/include/x86_64-linux-gnu/sys/stat.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <math.h>
#include <semaphore.h>
#include <immintrin.h>

#define ERR_KEY -11
#define FILE_ERR -12
#define BLOCK_SIZE 64
#define ENTERED_KEY_LENGTH 64
#define KEYS_SIZE 32
#define KEY_LENGTH 256
#define QUEUE_SIZE 8

typedef enum {
 CM_DECODE,
 CM_ENCODE,
} code_mode_t;

typedef enum {
   RM_SINGLE,
   RM_MULTI,
} run_mode_t;

typedef struct config_t {
  char * file_name;
  code_mode_t code_mode;
  run_mode_t run_mode;
  char * key;
  u_int32_t * iter_keys;
} config_t;

typedef struct block_t {
  u_int32_t left;
  u_int32_t right;
} block_t;

typedef struct queue_t {
  block_t queue[8];
  int head, tail;
  pthread_mutex_t head_mutex, tail_mutex;
  sem_t empty, full;
} queue_t;

typedef struct pc_context_t {
  config_t * config;
  queue_t queue;
  volatile int bytes_read;
  pthread_mutex_t tiq_mutex;
  pthread_mutex_t temp_file;
  pthread_cond_t tiq_cond;
  size_t file_size;
  FILE * file;
  FILE * temp;
} pc_context_t;

typedef bool (*password_handler_t) (void * context, block_t * task);

void queue_init (queue_t * queue) {
  queue->head = queue->tail = 0;
  pthread_mutex_init (&queue->head_mutex, NULL);
  pthread_mutex_init (&queue->tail_mutex, NULL);
  sem_init (&queue->empty, 0, QUEUE_SIZE);
  sem_init (&queue->full, 0, 0);
}

void queue_push (queue_t * queue, block_t * task) {
  sem_wait (&queue->empty);
  pthread_mutex_lock (&queue->tail_mutex);
  queue->queue[queue->tail] = *task;
  if (++queue->tail == QUEUE_SIZE)
    queue->tail = 0;
  pthread_mutex_unlock (&queue->tail_mutex);  
  sem_post (&queue->full);
}

void queue_pop (queue_t * queue, block_t * task) {
  sem_wait (&queue->full);
  pthread_mutex_lock (&queue->head_mutex);
  *task = queue->queue[queue->head];
  if (++queue->head == QUEUE_SIZE)
    queue->head = 0;
  pthread_mutex_unlock (&queue->head_mutex);
  sem_post (&queue->empty);
}

const unsigned char Pi[8][16] =
{
  {1,7,14,13,0,5,8,3,4,15,10,6,9,12,11,2},
  {8,14,2,5,6,9,1,12,15,4,11,0,13,10,3,7},
  {5,13,15,6,9,2,12,10,11,7,8,1,4,3,14,0},
  {7,15,5,10,8,1,6,13,0,9,3,14,11,4,2,12},
  {12,8,2,1,13,4,15,6,7,0,10,5,3,14,9,11},
  {11,3,5,8,2,15,10,13,14,1,7,4,12,9,6,0},
  {6,8,2,3,9,10,5,12,1,14,4,7,11,13,0,15},
  {12,4,6,2,10,5,11,9,14,8,13,7,0,3,15,1},
};

char * from_hex_to_bin(char * prepared_key, char * bin) { 
  char a;
  for (int i = 0; i < ENTERED_KEY_LENGTH; i++) {
    a = prepared_key[i];
    switch (a) {
    case '0':
      bin[4 * i] = '0';
      bin[4 * i + 1] = '0';
      bin[4 * i + 2] = '0';
      bin[4 * i + 3] = '0';
      break;
    case '1':
      bin[4 * i] = '0';
      bin[4 * i + 1] = '0';
      bin[4 * i + 2] = '0';
      bin[4 * i + 3] = '1';
      break; 
    case '2':
      bin[4 * i] = '0';
      bin[4 * i + 1] = '0';
      bin[4 * i + 2] = '1';
      bin[4 * i + 3] = '0';
      break;
    case '3':
      bin[4 * i] = '0';
      bin[4 * i + 1] = '0';
      bin[4 * i + 2] = '1';
      bin[4 * i + 3] = '1';
      break;
    case '4':
      bin[4 * i] = '0';
      bin[4 * i + 1] = '1';
      bin[4 * i + 2] = '0';
      bin[4 * i + 3] = '0';
      break;
    case '5':
      bin[4 * i] = '0';
      bin[4 * i + 1] = '1';
      bin[4 * i + 2] = '0';
      bin[4 * i + 3] = '1';
      break;
    case '6':
      bin[4 * i] = '0';
      bin[4 * i + 1] = '1';
      bin[4 * i + 2] = '1';
      bin[4 * i + 3] = '0';
      break;
    case '7':
      bin[4 * i] = '0';
      bin[4 * i + 1] = '1';
      bin[4 * i + 2] = '1';
      bin[4 * i + 3] = '1';
      break;
    case '8':
      bin[4 * i] = '1';
      bin[4 * i + 1] = '0';
      bin[4 * i + 2] = '0';
      bin[4 * i + 3] = '0';
      break;
    case '9':
      bin[4 * i] = '1';
      bin[4 * i + 1] = '0';
      bin[4 * i + 2] = '0';
      bin[4 * i + 3] = '1';
      break;
    case 'a':
      bin[4 * i] = '1';
      bin[4 * i + 1] = '0';
      bin[4 * i + 2] = '1';
      bin[4 * i + 3] = '0';
      break;
    case 'b':
      bin[4 * i] = '1';
      bin[4 * i + 1] = '0';
      bin[4 * i + 2] = '1';
      bin[4 * i + 3] = '1';
      break;
    case 'c':
      bin[4 * i] = '1';
      bin[4 * i + 1] = '1';
      bin[4 * i + 2] = '0';
      bin[4 * i + 3] = '0';
      break;
    case 'd':
      bin[4 * i] = '1';
      bin[4 * i + 1] = '1';
      bin[4 * i + 2] = '0';
      bin[4 * i + 3] = '1';
      break;
    case 'e':
      bin[4 * i] = '1';
      bin[4 * i + 1] = '1';
      bin[4 * i + 2] = '1';
      bin[4 * i + 3] = '0';
      break;
    case 'f':
      bin[4 * i] = '1';
      bin[4 * i + 1] = '1';
      bin[4 * i + 2] = '1';
      bin[4 * i + 3] = '1';
      break;
    }
  }
  return bin;
}

u_int32_t from_bin_to_dec (char * bin_key, u_int8_t first_idx, u_int8_t second_idx) {
  u_int32_t result = 0;
  u_int8_t j = 0;
  for (int i = second_idx; i >= first_idx; i--) {
    if (bin_key[i] == '1') {
      result += pow (2, j);
    }
    j++;
  }
  return result;
}

void get_block (block_t * block, u_int8_t * tmp_block) {
  int8_t i;
  for (i = 0; i < 3; i++) {
    block->left = block->left | tmp_block[i];
    block->left <<= 8;
  }
  block->left = block->left | tmp_block[i];
  for (i = 4; i < 7; i++) {
    block->right = block->right | tmp_block[i];
    block->right <<= 8;
  }
  block->right = block->right | tmp_block[i];
}

void transform_T (block_t * block) {
  u_int32_t tmp[32];
  int i;
  tmp[0] = (block->right & 0xF0000000) >> 28;
  tmp[1] = (block->right & 0x0F000000) >> 24;
  tmp[2] = (block->right & 0x00F00000) >> 20;
  tmp[3] = (block->right & 0x000F0000) >> 16;
  tmp[4] = (block->right & 0x0000F000) >> 12;
  tmp[5] = (block->right & 0x00000F00) >> 8;
  tmp[6] = (block->right & 0x000000F0) >> 4;
  tmp[7] = (block->right & 0x0000000F);

  for (i = 0; i < 8; i++) {
    if (i % 2 == 0) {
      tmp[i] = Pi[i * 2][tmp[i]];
    } else {
      tmp[i] = Pi[i * 2 + 1][tmp[i]];
    }
    tmp[i] <<= (7 - i) * 4;
  }
  
  block->right = tmp[0] | tmp[1] | tmp [2] | tmp[3]
    | tmp[5] | tmp[5] | tmp[6] | tmp[7];
}

void magma_block_transform_iter (config_t * config, block_t * block, size_t idx) {
  u_int32_t tmp;
  tmp = block->right;
  block->right = (block->right + config->iter_keys[idx]) & 0xFFFFFFFF;
  transform_T (block);
  block->right = (block->right << 11) | (block->right >> 21);
  block->right ^= block->left;
  block->left = tmp;
}

void magma_block_transform_iter_final (config_t * config, block_t * block) {
  u_int32_t tmp;
  tmp = block->right;
  switch (config->code_mode) {
  case CM_ENCODE:
    block->right = (block->right + config->iter_keys[KEYS_SIZE - 1]) & 0xFFFFFFFF;
    break;
  case CM_DECODE:
    block->right = (block->right + config->iter_keys[0]) & 0xFFFFFFFF;
    break;
  }
  transform_T (block);
  block->right = (block->right << 11) | (block->right >> 21);
  block->right ^= block->left;
  block->left = block->right;
  block->right = tmp;
}

void magma_block_transform (config_t * config, block_t * block) {
  int i;
  switch (config->code_mode) {
  case CM_ENCODE:
    for (i = 0; i < KEYS_SIZE - 1; i++) {
      magma_block_transform_iter (config, block, i);
    }
    magma_block_transform_iter_final (config, block);
  break;
  case CM_DECODE:
    for (i = KEYS_SIZE - 1; i > 0; i--) {
      magma_block_transform_iter (config, block, i);
    }
    magma_block_transform_iter_final (config, block);
    break;
  }
}

void copy_from_temp (FILE * file, FILE * temp, config_t * config, size_t file_size) {
  char ch;
  rewind (temp);
  size_t count = 0;
  switch (config->code_mode) {
    case CM_ENCODE:
      while (!feof (temp)) {
        ch = getc (temp);
        if (!feof (temp)) {
          putc (ch, file);
        } else break;
        }
      break;
      case CM_DECODE:
        while (count < file_size) {
        ch = getc (temp);
        ++count;
        putc (ch, file);
      }
      break;
  }
}

void iter_keys_create (config_t * config) {
  u_int32_t tmp;
  for (int i = 0; i < KEYS_SIZE / 4; i++) {
    tmp = from_bin_to_dec (config->key, i * KEYS_SIZE, (i + 1) * KEYS_SIZE - 1);
    config->iter_keys[i] = tmp;
    config->iter_keys[i + 8] = tmp;
    config->iter_keys[i + 16] = tmp; 
    config->iter_keys[KEYS_SIZE - i - 1] = tmp;
  }
}

void magma (config_t * config) {
  FILE * file = fopen (config->file_name, "rb");
  FILE * temp;
  if(!(temp = tmpfile())) {
    printf ("Cannot open temporary work file.\n");
    exit (FILE_ERR);
  }
  if (file == NULL) {
    printf ("%s\n", "Cannot open file.");
    exit (FILE_ERR);
  }
  int i;
  iter_keys_create(config);

  struct stat buff;
  fstat (fileno (file), &buff);
  block_t block = {
    .left = 0,
    .right = 0,
  };
  u_int8_t * tmp_block = malloc (BLOCK_SIZE / sizeof(u_int8_t));
  u_int32_t half_block;
  size_t bytes_read = 0;
  size_t file_size;

  switch (config->code_mode) {
    case CM_DECODE:
      fread(&file_size, sizeof(size_t), 1, file);
      break;
    case CM_ENCODE:
      file_size = buff.st_size;
      break;
  }
  while (bytes_read < file_size) {   
    memset(tmp_block, 0, sizeof(BLOCK_SIZE / sizeof(u_int8_t)));
    for (i = 0; i < 8; i++) {
      bytes_read += fread(&tmp_block[i], 1, 1, file);
    }
    get_block (&block, tmp_block);
    magma_block_transform (config, &block);
    for (i = 0; i < 4; i++) {
      half_block = (block.left >> 8 * (3 - i)) & 0xFF;
      fwrite (&half_block, sizeof(u_int8_t), 1, temp);
    }
    for (i = 0; i < 4; i++) {
      half_block = (block.right >> 8 * (3 - i)) & 0xFF;
      fwrite (&half_block, sizeof(u_int8_t), 1, temp);
    }
    block.left = 0;
    block.right = 0;
  }
  free (tmp_block);
  fclose (file);
  file = fopen (config->file_name, "wb");
  if (config->code_mode == CM_ENCODE)
    fwrite (&file_size, sizeof(size_t), 1, file);
  
  copy_from_temp (file, temp, config, file_size);
  fclose (file);
  fclose (temp);
  printf ("%s\n", "Done.");
}
////////////////////////////////////////////////
void * consumer (void * arg) {
  pc_context_t * pc_context = arg;
  config_t * config = pc_context->config;
  int i;
  u_int32_t half_block;
  for (;;) {
      block_t task;
      queue_pop (&pc_context->queue, &task);
      magma_block_transform (config, &task);
      pthread_mutex_lock(&pc_context->temp_file);
      for (i = 0; i < 4; i++) {
        half_block = (task.left >> 8 * (3 - i)) & 0xFF;
        fwrite (&half_block, sizeof(u_int8_t), 1, pc_context->temp);
      }
      for (i = 0; i < 4; i++) {
        half_block = (task.right >> 8 * (3 - i)) & 0xFF;
        fwrite (&half_block, sizeof(u_int8_t), 1, pc_context->temp);
      }
      pthread_mutex_unlock(&pc_context->temp_file);

      pthread_mutex_lock (&pc_context->tiq_mutex);
      pc_context->bytes_read -= 8;
      pthread_mutex_unlock (&pc_context->tiq_mutex);
      
      if (pc_context->bytes_read <= 0) {
        printf("signal\n");
	      pthread_cond_signal (&pc_context->tiq_cond);
      }
    }
}
////////////////////////////////////////////////
void magma_multi (config_t * config) {
  iter_keys_create(config);

  pc_context_t pc_context;
  pc_context.file = fopen (config->file_name, "rb");
  if(!(pc_context.temp = tmpfile())) {
    printf ("Cannot open temporary work file.\n");
    exit (FILE_ERR);
  }
  if (pc_context.file == NULL) {
    printf ("%s\n", "Cannot open file.");
    exit (FILE_ERR);
  }

  int i, num_cpu = sysconf (_SC_NPROCESSORS_ONLN); 
  pthread_t thread[num_cpu];
 
  pc_context.config = config;
  pc_context.bytes_read = 0;
  pthread_mutex_init (&pc_context.tiq_mutex, NULL);
  pthread_cond_init (&pc_context.tiq_cond, NULL);
  queue_init (&pc_context.queue);
  for (i = 0; i < num_cpu; ++i)
    pthread_create (&thread[i], NULL, consumer, &pc_context);

  struct stat buff;
  fstat (fileno (pc_context.file), &buff);
  block_t block = {
    .left = 0,
    .right = 0,
  };
  u_int8_t * tmp_block = malloc (BLOCK_SIZE / sizeof(u_int8_t));

  switch (config->code_mode) {
    case CM_DECODE:
      fread(&pc_context.file_size, sizeof(size_t), 1, pc_context.file);
      break;
    case CM_ENCODE:
      pc_context.file_size = buff.st_size;
      break;
  }

  while (pc_context.bytes_read < pc_context.file_size) {   
    memset(tmp_block, 0, sizeof(BLOCK_SIZE / sizeof(u_int8_t)));
    for (i = 0; i < 8; i++) {
      pc_context.bytes_read += fread(&tmp_block[i], 1, 1, pc_context.file);
    }
    get_block (&block, tmp_block);
    queue_push (&pc_context.queue, &block);
    block.left = 0;
    block.right = 0;
  }

  pthread_mutex_lock (&pc_context.tiq_mutex);
  while (pc_context.bytes_read >= 0) {
    pthread_cond_wait (&pc_context.tiq_cond, &pc_context.tiq_mutex);
    //printf("%d\n", pc_context.bytes_read);
  }
  for (i = 0; i < num_cpu; ++i) {
      printf ("%d\n", i);
      pthread_cancel (thread[i]);
      pthread_join (thread[i], NULL);
  }
  printf("ok2\n");
  free (tmp_block);
  fclose (pc_context.file);
  pc_context.file = fopen (config->file_name, "wb");
  if (config->code_mode == CM_ENCODE)
    fwrite (&pc_context.file_size, sizeof(size_t), 1, pc_context.file);
  
  copy_from_temp (pc_context.file, pc_context.temp, config, pc_context.file_size);
  printf ("%s\n", "Done.");
}

void get_key (char * prepared_key, config_t * config) {
  unsigned int key_length = strlen (prepared_key);

  if (key_length != ENTERED_KEY_LENGTH) {
    printf ("%s\n", "Incorrect key. Default key was used.");
    exit(ERR_KEY);
  }
  else {
    from_hex_to_bin (prepared_key, config->key);
  }
}

void parse_params (config_t * config, int argc, char * argv[]) {
  int opt;
  
  while ((opt = getopt(argc, argv, "f:k:edmg")) != -1) {
    switch (opt) {
    case 'f':
      config->file_name = optarg;
      break;
    case 'e':
      config->code_mode = CM_ENCODE;
      break;
    case 'd':
      config->code_mode = CM_DECODE;
      break;
    case 'k':
      get_key (optarg, config);     
      break;    
    case 'm':
      config->run_mode = RM_MULTI;
      break;
    }
  }
}

int main (int argc, char * argv[]) {	  
  printf ("%s\n", "Processing..");
  config_t config =
  {
   .file_name = "testfile.txt",
   .code_mode = CM_ENCODE,
   .iter_keys = malloc (KEYS_SIZE * 4),
   .run_mode = RM_SINGLE,
  };
  int i;

  config.key = malloc (KEY_LENGTH);
  for (i = 0; i < KEY_LENGTH; i++) {
    config.key[i] = 2;
  }

  parse_params (&config, argc, argv);

  switch (config.run_mode) {
  case RM_SINGLE:
    magma (&config);
    break;
  case RM_MULTI:
    magma_multi(&config);
    break;
  }

  free (config.iter_keys);
  free (config.key);
}
