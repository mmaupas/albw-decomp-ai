#include "../../shared/include/albw_types.h"

/* 0010F1F8 (48B, 119k hits): swap the two pointers' back-links:
 * if (n->a) n->a->b = n->b;  if (n->b) n->b->a = n->a;  n->a = 0; n->b = 0;
 * Target uses conditional loads/stores (ldrne/strne) — armcc produces
 * those from `if (p) q->field = ...` when it can't prove p non-null. */
typedef struct Node {
    struct Node* a;   /* 0x00 */
    struct Node* b;   /* 0x04 */
} Node;

void func_0010F1F8(Node* n) {
    if (n->a) n->a->b = n->b;
    if (n->b) n->b->a = n->a;
    n->b = 0;
    n->a = 0;
}
