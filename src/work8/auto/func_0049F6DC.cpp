// 0x49F6DC: sentinel insert-after: self->next = n; n->prev=self;
// n->next=old_next; if(old_next) old_next->prev=n.
struct Node { Node* prev; Node* next; };
extern "C" void target(Node* self, Node* n) {
    Node* nx = self->next;
    self->next = n;
    n->prev = self;
    n->next = nx;
    if (nx) nx->prev = n;
}
