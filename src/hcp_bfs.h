#ifndef HCP_BFS_H_
#define HCP_BFS_H_

#include "hcp.h"

struct hcp_bfs_struct;
typedef struct hcp_bfs_struct hcp_bfs_s, *hcp_bfs;

hcp_bfs hcp_bfs_create(hcp hcp);
void hcp_bfs_destroy(hcp_bfs bfs);

#endif /* HCP_BFS_H_ */
