// 0x10F1DC: s->head = n FIRST.
struct Node { Node* next; Node* prev; };
struct S { Node* head; };
extern "C" void target(S* s, Node* n) {
    Node* h = s->head;
    s->head = n;
    n->prev = (Node*)s;
    n->next = h;
    if (h) h->prev = n;
}
