#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>

#include "re2dfa.h"

/*******************************************************************************
******************               Basic Function               ******************
*******************************************************************************/

static int __cmp_addr_int_ptr(const void *a_, const void *b_)
{
    int* a = *((int**) a_);
    int* b = *((int**) b_);
    if (a < b) return -1;
    else if (a > b) return 1;
    else return 0;
}

static int __cmp_addr_NFA_state_ptr(const void *a_, const void *b_)
{
    struct NFA_state* a = *((struct NFA_state**) a_);
    struct NFA_state* b = *((struct NFA_state**) b_);
    if (a < b) return -1;
    else if (a > b) return 1;
    else return 0;
}

static int __cmp_addr_DFA_state_ptr(const void *a_, const void *b_)
{
    struct DFA_state* a = *((struct DFA_state**) a_);
    struct DFA_state* b = *((struct DFA_state**) b_);
    if (a < b) return -1;
    else if (a > b) return 1;
    else return 0;
}

static int __cmp_char_char(const void *a_, const void *b_)
{
    char a = *((char*) a_);
    char b = *((char*) b_);
    if (a < b) return -1;
    else if (a > b) return 1;
    else return 0;
}

/*******************************************************************************
******************           Generic-List Function            ******************
*******************************************************************************/

/* Create a generic list for some kind of data elements, elem_size specified
 * the size in bytes of each data element, initial_capacity is the amount of
 * space reserved for furture use (it cannot be zero). */
void __create_generic_list(
    int elem_size, int initial_capacity, struct generic_list *glist)
{
    assert(initial_capacity != 0);    /* zero capacity list would not be
                                       * correctly expanded */
    glist->elem_size = elem_size;
    glist->capacity  = initial_capacity;
    glist->length    = 0;
    glist->p_dat     = (char*)malloc(elem_size * initial_capacity);
}

/* "Copy constructor" */
void generic_list_duplicate(
    struct generic_list *dest, const struct generic_list *src)
{
    __create_generic_list(src->elem_size, src->capacity, dest);
    dest->length = src->length;
    memcpy(dest->p_dat, src->p_dat, src->length * src->elem_size);
}

/* Free the memory allocated for the generic list */
void destroy_generic_list(struct generic_list *glist) {
    free(glist->p_dat);
}

/* Append an element to the tail of specified generic list */
void generic_list_push_back(struct generic_list *glist, const void *elem)
{
    /* if we're running out of space */
    if (glist->capacity == glist->length)
    {
        glist->capacity *= 2;   /* expand two-fold */
        glist->p_dat =
            (char*)realloc(glist->p_dat, glist->elem_size * glist->capacity);
    }

    /* append *elem to the tail of glist */
    memcpy(
        glist->p_dat + glist->elem_size * glist->length++, elem,
        glist->elem_size);
}

/* Remove the last element in the list */
void generic_list_pop_back(struct generic_list *glist)
{
    assert(glist->length != 0);  /* check for stack downflow */
    glist->length -= 1;
}

/* Get the pointer to the element on the tail of the list */
void *generic_list_back(struct generic_list *glist)
{
    assert(glist->length != 0);
    return glist->p_dat + glist->elem_size * (glist->length - 1);
}

/* Get pointer to the first element  */
void *generic_list_front(struct generic_list *glist)
{
    assert(glist->length != 0);
    return glist->p_dat;
}

/* Empty the generic list */
void generic_list_clear(struct generic_list *glist) {
    glist->length = 0;
}

/* Find element in the list using specified compare function, it returns the
 * pointer to the element found in the list, or a NULL is returned if *elem is
 * not in glist */
void *generic_list_find(
    struct generic_list *glist, const void *elem,
    int(*cmp)(const void*, const void*))
{
    int i = 0;
    char *cur = glist->p_dat;

    for ( ; i < glist->length; i++, cur += glist->elem_size) {
        if (cmp((void*)cur, elem) == 0) return cur;  /* found */
    }

    return NULL;   /* not found */
}

/* Add an element to the list only if this element is not in the list (we
 * actually regard the glist as a set). It would return 1 if *elem is actually
 * appended, or it would return 0 when there's already an *elem in the list. */
int generic_list_add(
    struct generic_list *glist, const void *elem,
    int(*cmp)(const void*, const void*))
{
    /* see if elem is already in the list*/
    void *p_same = generic_list_find(glist, elem, cmp);

    if (p_same == NULL)
    {
        /* elem not in the list, so append it */
        generic_list_push_back(glist, elem);
        return 1;
    }
    else {
        return 0;  /* elem already in the list, do nothing */
    }
}

/*******************************************************************************
******************                NFA Function                ******************
*******************************************************************************/

/* LL(1) parser modules */
static struct NFA __LL_expression(char **statement);
static struct NFA __LL_term(char **statement);
static struct NFA __LL_primary(char **statement);

/* expression:
       expression term
       expression | term
       term                */
static struct NFA __LL_expression(char **statement)
{
    struct NFA lhs = __LL_term(statement);
    struct NFA ret, rhs;
    char ch;

    for ( ; ; lhs = ret)
    {
        ch = **statement;

        if (isalnum(ch) || ch == '(') { /* expression term */
            rhs = __LL_term(statement);
            ret = NFA_concatenate(&lhs, &rhs);
        }
        else if (ch == '|') {           /* expression | term */
            *statement += 1;            /* eat '|' */
            rhs = __LL_term(statement);
            ret = NFA_alternate(&lhs, &rhs);
        }
        else {
            return lhs;                 /* term  */
        }
    }

    return ret;   /* we should never reach here */
}

/* term:
       term *
       term +
       primary    */
static struct NFA __LL_term(char **statement)
{
    struct NFA lhs = __LL_primary(statement);
    struct NFA ret;
    char ch = **statement;

    if (ch == '*') {            /* term * */
        ret = NFA_Kleene_closure(&lhs);
        *statement += 1;        /* eat the Kleene star */
    }
    else if (ch == '+') {       /* term + */
        ret = NFA_positive_closure(&lhs);
        *statement += 1;        /* eat the positive closure */
    }
    else if (ch == '?') {       /* term ? */
        ret = NFA_optional(&lhs);
        *statement += 1;        /* eat the optional (question) mark */
    }
    else {
        return lhs;             /* primary */
    }

    return ret;
}

/* primary:
       ALNUM
       ( expression )    */
static struct NFA __LL_primary(char **statement)
{
    struct NFA ret;
    char ch = **statement;

    if (isalnum(ch)) {          /* ALNUM */
        ret = NFA_create_atomic(ch);
        *statement += 1;        /* eat the character */
    }
    else if (ch == '(')         /* ( expression ) */
    {
        *statement += 1;        /* eat '(' */
        ret = __LL_expression(statement);
        if (**statement != ')') {
            fprintf(stderr, "no matching ')' found\n"); exit(-1);
        }
        *statement +=1;         /* eat ')' */
    }
    else {
        fprintf(stderr, "unrecognized character \"%c\"\n", ch);
        exit(-1);
    }

    return ret;
}

/* LL parser driver/interface */
struct NFA reg_to_NFA(const char *regexp)
{
    char **cur = (char **)(&regexp);
    struct NFA nfa = __LL_expression(cur); /* creating NFA for regexp is just
                                            * like assembling building blocks
                                            * as what the regexp says */

    if (**cur != '\0') {
        fprintf(stderr, "unexcepted character \"%c\"\n", **cur);
        exit(-1);
    }

    return nfa;
}

/* dump the transition from state to state->to[i_to] */
static void __NFA_transition_dump_graphviz(
    const struct NFA_state *state, int i_to, FILE *fp)
{
    switch (state->transition[i_to].trans_type)
    {
    case NFATT_EPSILON:
        fprintf(fp, "    addr_%p -> addr_%p [ label = \"epsilon\" ];\n",
            (void*)state,
            (void*)state->to[i_to]);
        break;

    case NFATT_CHARACTER:
        fprintf(fp, "    addr_%p -> addr_%p [ label = \"%c\" ];\n",
            (void*)state,
            (void*)state->to[i_to],
            state->transition[i_to].trans_char);
        break;

    default:
        abort();  /* you should never reach here */
    }
}

/* dump the transitions to *all reachable* states from specified state */
static void __NFA_reachable_states_dump_graphviz(
    const struct NFA_state *state, struct generic_list *visited, FILE *fp)
{
    int n_to = NFA_state_transition_num(state);
    int i_to = 0;

    for ( ; i_to < n_to; i_to++)
    {
        /* dump this transition */
        __NFA_transition_dump_graphviz(state, i_to, fp);

        /* dump the transition target if it has not ever been dumped, exactly
         * the same way with DFS. */
        if (generic_list_add(
                visited, &state->to[i_to], __cmp_addr_DFA_state_ptr) != 0) {
            __NFA_reachable_states_dump_graphviz(state->to[i_to], visited, fp);
        }
    }
}

/* Dump DOT code to vizualize specified NFA */
void NFA_dump_graphviz_code(const struct NFA *nfa, FILE *fp)
{
    struct generic_list visited_state;
    create_generic_list(struct NFA_state*, &visited_state);

    fprintf(fp,
        "digraph finite_state_machine {\n"
        "    rankdir=LR;\n"
        "    size=\"8,5\"\n"
        "    node [shape = doublecircle label=\"\"]; addr_%p\n"
        "    node [shape = circle]\n", (void*)nfa->terminate);

    /* dump the finite state machine recursively */
    generic_list_push_back(&visited_state, &nfa->start);
    __NFA_reachable_states_dump_graphviz(nfa->start, &visited_state, fp);

    /* dump start mark */
    fprintf(fp, "    node [shape = none label=\"\"]; start\n");
    fprintf(fp, "    start -> addr_%p [ label = \"start\" ]\n",
        (void*)nfa->start);

    /* done */
    fprintf(fp, "}\n");
    destroy_generic_list(&visited_state);
}

/* Match the given substring in a recursive fasion */
static int __NFA_is_substate_match(
    const struct NFA_state *state, const char *str)
{
    char c = str[0];  /* transition to match */
    int i_trans = 0, n_trans = NFA_state_transition_num(state);
    int is_matched = 0;

    /* If we reached the terminate state while consumed the entire string*/
    if (c == '\0' && n_trans == 0)   return 1;   /* str matched the nfa */

    for ( ; i_trans < n_trans; i_trans++)
    {
        /* if it is an epsilon move, we can take this way instantly */
        if (state->transition[i_trans].trans_type == NFATT_EPSILON) {
            is_matched = __NFA_is_substate_match(state->to[i_trans], str);
        }
        /* or it must be a character transition, check if we can take it */
        else if (state->transition[i_trans].trans_char == c) {
            is_matched = __NFA_is_substate_match(state->to[i_trans], str + 1);
        }

        if (is_matched) return 1;
    }

    return 0;  /* not matched */
}

/* Check if the string matches the pattern implied by the nfa */
int NFA_pattern_match(const struct NFA *nfa, const char *str)
{
    /* find a sequence of transitions recursively */
    return __NFA_is_substate_match(nfa->start, str);
}

/* Create a new isolated NFA state, there's no transitions going out of it */
struct NFA_state *alloc_NFA_state(void)
{
    struct NFA_state *state =
        (struct NFA_state*)malloc(sizeof(struct NFA_state));
    struct NFA_transition null_transition = {NFATT_NONE, 0};

    /* create an isolated NFA state node */
    state->to[0] = state->to[1] = NULL;
    state->transition[0] = state->transition[1] = null_transition;

    return state;
}

/* Free allocated space for specified NFA state */
void free_NFA_state(struct NFA_state *state) {
    free(state);
}

/* get number of transitions going out from specified NFA state */
int NFA_state_transition_num(const struct NFA_state *state)
{
    if (state->transition[1].trans_type != NFATT_NONE) return 2;
    if (state->transition[0].trans_type != NFATT_NONE) return 1;
    else  return 0;
}

/* Add another transition to specified NFA state, this function returns 0 on
 * success, or it would return an -1 when there's already 2 transitions going
 * out of this state */
int NFA_state_add_transition(struct NFA_state *state,
    enum NFA_transition_type trans_type, char trans_char,
    struct NFA_state *to_state)
{
    int i_trans = NFA_state_transition_num(state);
    if (i_trans >= 2)  return -1;  /* no empty slot avaliable */
    else {
        state->transition[i_trans].trans_type = trans_type;
        state->transition[i_trans].trans_char = trans_char;
        state->to[i_trans]                    = to_state;
        return 0;
    }
}

/* Add an epsilon transition from "from" to "to */
int NFA_epsilon_move(struct NFA_state *from, struct NFA_state *to)
{
    return NFA_state_add_transition(from, NFATT_EPSILON, 0, to);
}

/* DEBUGGING ROUTINE: dump specified NFA state to fp */
void __dump_NFA_state(const struct NFA_state *state, FILE *fp)
{
    int n_trans = NFA_state_transition_num(state);
    int i_trans = 0;

    fprintf(fp, "num of transitions: %d\n", n_trans);
    for ( ; i_trans < n_trans; i_trans++)
    {
        switch (state->transition[i_trans].trans_type)
        {
        case NFATT_CHARACTER:
            fprintf(fp, "   alphabet transition: %c\n",
                state->transition[i_trans].trans_char);
            break;

        case NFATT_EPSILON:
            fprintf(fp, "   epsilon transition\n");
            break;

        default:
            fprintf(fp, "ERROR: You should never reach here\n");
            abort();
        }
    }
}

/* Create an NFA for recognizing single character */
struct NFA NFA_create_atomic(char c)
{
    struct NFA nfa;

    nfa.start     = alloc_NFA_state();
    nfa.terminate = alloc_NFA_state();

    assert(c != '\0');
    NFA_state_add_transition(nfa.start, NFATT_CHARACTER, c, nfa.terminate);

    return nfa;
}

/* C = AB */
struct NFA NFA_concatenate(const struct NFA *A, const struct NFA *B)
{
    struct NFA C;
    C.start     = A->start;
    C.terminate = B->terminate;

    NFA_epsilon_move(A->terminate, B->start);

    return C;
}

/* C = A|B */
struct NFA NFA_alternate(const struct NFA *A, const struct NFA *B)
{
    struct NFA C;
    C.start     = alloc_NFA_state();
    C.terminate = alloc_NFA_state();

    NFA_epsilon_move(C.start,      A->start);
    NFA_epsilon_move(C.start,      B->start);
    NFA_epsilon_move(A->terminate, C.terminate);
    NFA_epsilon_move(B->terminate, C.terminate);

    return C;
}

/* C = A? = A|epsilon */
struct NFA NFA_optional(const struct NFA *A)
{
    struct NFA C;
    C.start     = alloc_NFA_state();
    C.terminate = A->terminate;

    NFA_epsilon_move(C.start, A->start);
    NFA_epsilon_move(C.start, A->terminate);

    return C;
}

/* C = A* */
struct NFA NFA_Kleene_closure(const struct NFA *A)
{
    struct NFA C;
    C.start     = alloc_NFA_state();
    C.terminate = alloc_NFA_state();

    NFA_epsilon_move(A->terminate, C.start);
    NFA_epsilon_move(C.start,      A->start);
    NFA_epsilon_move(C.start,      C.terminate);

    return C;
}

/* C = A+ = AA* */
struct NFA NFA_positive_closure(const struct NFA *A)
{
    struct NFA C;
    C.start     = alloc_NFA_state();
    C.terminate = alloc_NFA_state();

    NFA_epsilon_move(C.start,      A->start);
    NFA_epsilon_move(A->terminate, C.start);
    NFA_epsilon_move(A->terminate, C.terminate);

    return C;
}

/* Traverse the NFA while recording addresses of all states in a generic
 * list */
static void __NFA_traverse(
    struct NFA_state *state, struct generic_list *visited)
{
    int i_to = 0, n_to = NFA_state_transition_num(state);
    for ( ; i_to < n_to; i_to++)
    {
        /* DFS of graphs */
        if (generic_list_add(
                visited, &state->to[i_to], __cmp_addr_int_ptr) != 0) {
            __NFA_traverse(state->to[i_to], visited);
        }
    }
}

/* Free an NFA */
void NFA_dispose(struct NFA *nfa)
{
    struct generic_list visited;

    struct NFA_state **cur;
    int i_state = 0;

    /* traverse the NFA and record all states in a generic list */
    create_generic_list(struct NFA_state*, &visited);
    generic_list_push_back(&visited, &nfa->start);
    __NFA_traverse(nfa->start, &visited);

    /* free all states */
    for (cur = (struct NFA_state**) visited.p_dat;
         i_state < visited.length; i_state++, cur++)
    {
        free_NFA_state(*cur);
    }

    destroy_generic_list(&visited);
}
/*******************************************************************************
******************                DFA Function                ******************
*******************************************************************************/

/* Other DFA corresponding functions */

static struct __DFA_state_set *__alloc_stateset_node(void)
{
    struct __DFA_state_set *new_node = 
        (struct __DFA_state_set *) malloc(sizeof(struct __DFA_state_set));

    new_node->prev = new_node->next = NULL;
    new_node->dfa_states.length = 0;
    new_node->merged_state = NULL;

    return new_node;
}

static struct __DFA_state_set *__create_empty_stateset_list(void)
{
    struct __DFA_state_set *head = __alloc_stateset_node();
    head->prev = head->next = head;

    return head;
}

static void __free_DFA_state_set(struct __DFA_state_set *state_set)
{
    destroy_generic_list(&state_set->dfa_states);
    free(state_set);
}

static void __destroy_DFA_stateset_list(struct __DFA_state_set *head)
{
    struct __DFA_state_set *cur = head->next, *next;
    free(head);           /* free head node first  */

    /* then free the rest of the list */
    for ( ; cur != head; cur = next)
    {
        next = cur->next;
        __free_DFA_state_set(cur);
    }    
}

static struct __DFA_state_set *__find_state_set(
    struct __DFA_state_set *ll_head, const struct DFA_state *state)
{
    struct __DFA_state_set *cur = ll_head->next;
    for ( ; cur != ll_head; cur = cur->next)
    {
        if (generic_list_find(&cur->dfa_states,
                              &state, __cmp_addr_DFA_state_ptr) != NULL) {
            return cur;
        }
    }

    return NULL;
}

static void __insert_DFA_state_set_after(
    struct __DFA_state_set *e, struct __DFA_state_set *pivot)
{
    e->prev = pivot;
    e->next = pivot->next;
    pivot->next->prev = e;
    pivot->next = e;
}

static void __insert_states_after(
    const struct generic_list *states, struct __DFA_state_set *pivot)
{
    struct __DFA_state_set *new_node = __alloc_stateset_node();

    new_node->dfa_states = *states;
    __insert_DFA_state_set_after(new_node, pivot);
}

static void __remove_DFA_state_set(struct __DFA_state_set *state_set)
{
    state_set->prev->next = state_set->next;
    state_set->next->prev = state_set->prev;
    
    __free_DFA_state_set(state_set);
}

/* Create a new DFA state and bind it with specified set of NFA states */
static void __create_dfa_state_entry(
    const struct generic_list *states, struct __dfa_state_entry *entry)
{
    /* the dfa state entry object keeps a copy of NFA state labels (addrs) and
     * sort these labels for fast set comparisons */
    generic_list_duplicate(&entry->nfa_states, states);
    qsort(
        entry->nfa_states.p_dat,
        entry->nfa_states.length,
        entry->nfa_states.elem_size,
        __cmp_addr_NFA_state_ptr);

    /* create a new DFA state for this set of NFA states */
    entry->dfa_state = alloc_DFA_state();
}

/* Free memory allocated for the entry object */
static void __destroy_dfa_state_entry(struct __dfa_state_entry *entry) {
    destroy_generic_list(&entry->nfa_states);
}

/* compare if two generic lists are equivalent:
     (set(label_a) == set(label_b))
*/
static int __cmp_dfa_state_entry(const void *a_, const void *b_)
{
    struct NFA_state **sa, **sb;
    int i = 0, length;

    struct __dfa_state_entry *a = (struct __dfa_state_entry*) a_;
    struct __dfa_state_entry *b = (struct __dfa_state_entry*) b_;

    struct generic_list *label_a = &a->nfa_states;
    struct generic_list *label_b = &b->nfa_states;

    if (label_a->length != label_b->length) return 1;   /* not equal */

    /* compare the elements of the states label list */
    length = label_a->length;
    for (sa = (struct NFA_state **)label_a->p_dat,
             sb = (struct NFA_state **)label_b->p_dat;
         i < length; i++, sa++, sb++)
    {
        if (*sa != *sb) return 1;
    }

    return 0;  /* a_ == b_ */
}

/* Calculate the epsilon closure of specified state, all states in the
 * resulting closure are appended to the visited list */
static void __NFA_state_epsilon_closure(
    const struct NFA_state *state, struct generic_list *visited)
{
    int i_trans = 0, n_trans = NFA_state_transition_num(state);

    for ( ; i_trans < n_trans; i_trans++)
    {
        if (state->transition[i_trans].trans_type == NFATT_EPSILON)
        {
            /* storm down if we have not visited this state yet */
            if (generic_list_add(
                visited, &state->to[i_trans], __cmp_addr_NFA_state_ptr) != 0) {
                __NFA_state_epsilon_closure(state->to[i_trans], visited);
            }
        }
    }
}

/* Figure out the epsilon closure of a set of states. */
static void __NFA_epsilon_closure(struct generic_list *states)
{
    const struct NFA_state *state;
    int i_state = 0, n_state = states->length;

    for ( ; i_state < n_state; i_state++)
    {
        /* states->p_dat might be relocated while appending more elements */
        state = *(((const struct NFA_state**) states->p_dat) + i_state);
        __NFA_state_epsilon_closure(state, states);
    }
}

/* Get all possible transitions from specified set of states */
static void __NFA_collect_transition_chars(
    struct generic_list *states, struct generic_list *trans_char)
{
    struct NFA_state **s = (struct NFA_state**) states->p_dat;

    int i_state = 0, i_trans;
    int n_states = states->length, n_trans;

    for ( ; i_state < n_states; i_state++, s++)
    {
        n_trans = NFA_state_transition_num(*s);
        for (i_trans = 0; i_trans < n_trans; i_trans++)
        {
            if ((*s)->transition[i_trans].trans_type == NFATT_CHARACTER)
            {
                generic_list_add(
                    trans_char,
                    &((*s)->transition[i_trans].trans_char),
                    __cmp_char_char);
            }
        }
    }
}

/* Get all possible successor states under transition c to a set of given
 * states */
static void __NFA_collect_target_states(
    struct generic_list *states, char c, struct generic_list *new_states)
{
    struct NFA_state **s = (struct NFA_state**) states->p_dat;

    int i_state = 0, i_trans;
    int n_states = states->length, n_trans;

    for ( ; i_state < n_states; i_state++, s++)
    {
        n_trans = NFA_state_transition_num(*s);
        for (i_trans = 0; i_trans < n_trans; i_trans++)
        {
            if ((*s)->transition[i_trans].trans_type == NFATT_CHARACTER &&
                (*s)->transition[i_trans].trans_char == c)
            {
                generic_list_add(
                    new_states, &((*s)->to[i_trans]), __cmp_addr_NFA_state_ptr);
            }
        }
    }
}

static struct DFA_state *__get_DFA_state_address(
    struct generic_list *dfa_state_entry_list,
    const struct generic_list *states, int *is_new_entry)
{
    struct __dfa_state_entry entry, *addr;
    __create_dfa_state_entry(states, &entry);

    /* search in all logged entries first */
    addr = (struct __dfa_state_entry *)
        generic_list_find(dfa_state_entry_list, &entry, __cmp_dfa_state_entry);

    if (addr == NULL)    /* not found, we need to add a new entry/DFA state */
    {
        *is_new_entry = 1;
        generic_list_push_back(dfa_state_entry_list, &entry);
        return entry.dfa_state;
    }
    else                 /* entry/DFA state already exists */
    {
        *is_new_entry = 0;
        __destroy_dfa_state_entry(&entry);
        free_DFA_state(entry.dfa_state);
        return addr->dfa_state;
    }
}

/* Mark DFA states containing the terminate state of NFA as acceptable */
static void __mark_acceptable_states(
    const struct NFA_state *terminator,
    struct generic_list *dfa_state_entry_list)
{
    struct __dfa_state_entry *entry;

    int i_entry = 0;
    for (entry = (struct __dfa_state_entry *) dfa_state_entry_list->p_dat;
         i_entry < dfa_state_entry_list->length; i_entry++, entry++)
    {
        /* check if the terminator of NFA is merged into this DFA state */
        if (generic_list_find(
            &entry->nfa_states, &terminator, __cmp_addr_NFA_state_ptr) != NULL)
        {
            /* if so, this DFA state becomes acceptable */
            DFA_make_acceptable(entry->dfa_state);
        }
    }
}

static void __NFA_to_DFA_rec(
    struct generic_list *states,
    struct generic_list *dfa_state_entry_list)
{
    struct generic_list trans_char, new_states;
    struct DFA_state *from, *to;
    int  i_char = 0;
    int  if_rec, dummy;  /* if this state has already been created */
    char *c;

    create_generic_list(char, &trans_char);
    create_generic_list(struct NFA_state*, &new_states);

    /* get all transition characters in states, we gonna storm each way down in
     * the next for loop. */
    __NFA_collect_transition_chars(states, &trans_char);

    for (c = (char*)trans_char.p_dat;
         i_char < trans_char.length; i_char++, c++)
    {
        /* get the epsilon closure of target states under transition *c */
        __NFA_collect_target_states(states, *c, &new_states);
        __NFA_epsilon_closure(&new_states);

        /* Here we need to add states and new_states to the DFA, and connect
         * them together with transition. */
        from = __get_DFA_state_address(dfa_state_entry_list, states, &dummy);
        to   = __get_DFA_state_address(dfa_state_entry_list, &new_states, &if_rec);
        DFA_add_transition(from, to, *c);

        /* DFS: storm down this way and get its all successor states */
        if (if_rec)
            __NFA_to_DFA_rec(&new_states, dfa_state_entry_list);

        generic_list_clear(&new_states);
    }

    destroy_generic_list(&trans_char);
    destroy_generic_list(&new_states);
}

/* Convert an NFA to DFA, this function returns the start state of the
 * resulting DFA */
struct DFA_state *NFA_to_DFA(const struct NFA *nfa)
{
    int i_list = 0;
    struct generic_list start_states;
    struct generic_list dfa_state_entry_list;
    struct DFA_state *dfa_start_state;

    create_generic_list(struct NFA_state*, &start_states);
    create_generic_list(struct __dfa_state_entry, &dfa_state_entry_list);

    /* recursive: we start from the epsilon closure of the start state and
     * storm all the way down. */
    generic_list_push_back(&start_states, &nfa->start);
    __NFA_epsilon_closure(&start_states);
    __NFA_to_DFA_rec(&start_states, &dfa_state_entry_list);

    /* mark DFA states containing the terminate state of NFA as acceptable */
    __mark_acceptable_states(nfa->terminate, &dfa_state_entry_list);

    /* start state of generated DFA should be the first created one */
    dfa_start_state =
        ((struct __dfa_state_entry*) dfa_state_entry_list.p_dat)[0].dfa_state;

    /* The final clean ups */
    for ( ; i_list < dfa_state_entry_list.length; i_list++)
    {
        /* we need to destroy all sublists */
        __destroy_dfa_state_entry(
            ((struct __dfa_state_entry *) dfa_state_entry_list.p_dat) + i_list);
    }

    destroy_generic_list(&start_states);
    destroy_generic_list(&dfa_state_entry_list);

    return dfa_start_state;
}

/* Create an empty (isolated), non-acceptable state */
struct DFA_state *alloc_DFA_state(void)
{
    struct DFA_state *state =
        (struct DFA_state*)malloc(sizeof(struct DFA_state));

    state->_capacity = 4;
    state->n_transitions = 0;   /* isolated  */
    state->is_acceptable = 0;   /* non-acceptable */
    state->trans = (struct DFA_transition*)malloc(
        state->_capacity * sizeof(struct DFA_transition));

    return state;
}

/* Free allocated space for specified DFA state */
void free_DFA_state(struct DFA_state *state)
{
    free(state->trans);         /* free array of transitions */
    free(state);                /* free the state object */
}

/* Traverse from specified state and add all reachable states to a generic
 * list */
void DFA_traverse(
    struct DFA_state *state, struct generic_list *visited)
{
    int i_trans = 0, n_trans = state->n_transitions;
    for ( ; i_trans < n_trans; i_trans++)
    {
        /* DFS */
        if (generic_list_add(
            visited, &state->trans[i_trans].to, __cmp_addr_DFA_state_ptr
            ) != 0) {
            DFA_traverse(state->trans[i_trans].to, visited);
        }
    }
}

/* stuff all transition characters emitted by specified state to trans_chars */
static void __DFA_state_collect_transition_chars(
    const struct DFA_state *state, struct generic_list *trans_chars)
{
    int i_trans = 0;
    for ( ; i_trans < state->n_transitions; i_trans++)
    {
        generic_list_add(
            trans_chars, &state->trans[i_trans].trans_char,
            __cmp_char_char);
    }
}

/* Collect all transition chars of states in specified state set */
static void DFA_states_collect_transition_chars(
    const struct generic_list *states, struct generic_list *trans_chars)
{
    struct DFA_state **state = (struct DFA_state **) states->p_dat;
    int i_state = 0, n_states = states->length;

    for ( ; i_state < n_states; i_state++, state++) {
        __DFA_state_collect_transition_chars(*state, trans_chars);
    }
}

/* Initialize 2 state sets for DFA optimization process, one for all
 * non-acceptable states, one for the rest of them (acceptable states). */
static struct __DFA_state_set *initialize_DFA_state_set(
    struct DFA_state *dfa_start)
{
    int i_state = 0, n_state;
    struct generic_list state_list, acceptable, nonacceptable;
    struct DFA_state **state;
    struct __DFA_state_set *ll_state_set = __create_empty_stateset_list();

    create_generic_list(struct DFA_state *, &state_list);
    create_generic_list(struct DFA_state *, &acceptable);
    create_generic_list(struct DFA_state *, &nonacceptable);

    /* get all states in the DFA */
    generic_list_push_back(&state_list, &dfa_start);
    DFA_traverse(dfa_start, &state_list);

    /* Initialize state sets by placing all acceptable states to the acceptable
     * list, non-acceptable states goes to nonacceptable list */
    n_state = state_list.length;
    for (state = (struct DFA_state **) state_list.p_dat;
         i_state < n_state; i_state++, state++)
    {
        (*state)->is_acceptable ?
            generic_list_push_back(&acceptable,    state):
            generic_list_push_back(&nonacceptable, state);
    }

    /* we've done constructing the 2 initial state sets */
    (acceptable.length != 0) ?
        __insert_states_after(&acceptable, ll_state_set):
        destroy_generic_list(&acceptable);

    (nonacceptable.length != 0) ?
        __insert_states_after(&nonacceptable, ll_state_set):
        destroy_generic_list(&nonacceptable);

    destroy_generic_list(&state_list);
    return ll_state_set;
}

/* Split state_set to 2 distinguishable state sets by looking at if states in
 * state_set are distinguishable under transition c

                   c   state_split_0
       state_set ----<
                       state_split_1
 */
static int split_distinguishable_states(
    struct __DFA_state_set *ll_head,
    struct __DFA_state_set *state_set, char c)
{
    struct generic_list state_split_0, state_split_1;

    struct DFA_state
        **state = (struct DFA_state**)(state_set->dfa_states.p_dat),
        *target;

    struct __DFA_state_set *ref;

    int i_state = 0, n_states = state_set->dfa_states.length;

    create_generic_list(struct DFA_state *, &state_split_0);
    create_generic_list(struct DFA_state *, &state_split_1);

    /* use the first state as reference state, all states transiting to ref
     * goes to state_split_0, otherwise pushed to state_split_1 */
    ref = __find_state_set(ll_head, DFA_target_of_trans(*state, c));
    generic_list_push_back(&state_split_0, state);

    i_state++, state++;
    for ( ; i_state < n_states; i_state++, state++)
    {
        target = DFA_target_of_trans(*state, c);

        if (ref != NULL)
            if (target != NULL)
                /* test if this state is distinguishable with ref state under
                 * transition c */
                ref == __find_state_set(ll_head, target) ?
                    generic_list_push_back(&state_split_0, state):
                    generic_list_push_back(&state_split_1, state);

            else   /* no such transition, distinguishable */
                generic_list_push_back(&state_split_1, state);

        else
            target != NULL ?
                generic_list_push_back(&state_split_1, state):
                generic_list_push_back(&state_split_0, state);
    }

    /* we're done splitting the state set, now it's time to submit our
     * changes */
    if (state_split_1.length != 0) /* if we really splitted state_set to 2
                                    * distinguishable states */
    {
        __insert_states_after(&state_split_1, state_set);
        __insert_states_after(&state_split_0, state_set);
        __remove_DFA_state_set(state_set);
        return 1;
    }
    else                        /* not splitted, no change to commit */
    {
        destroy_generic_list(&state_split_0);
        destroy_generic_list(&state_split_1);
        return 0;
    }
}

/* Split the state set into 2 distinguishable sets, splitted sets might also be
 * splitable. */
static int split_state_set(
    struct __DFA_state_set *ll_head, struct __DFA_state_set *state_set)
{
    struct generic_list trans_chars;
    int i_char = 0, n_chars;
    char *c;

    create_generic_list(char, &trans_chars);
    DFA_states_collect_transition_chars(&state_set->dfa_states, &trans_chars);

    /* investigate every possible transitions to find distinguishable states */
    n_chars = trans_chars.length;
    for (c = (char*)trans_chars.p_dat; i_char < n_chars; i_char++, c++)
    {
        if (split_distinguishable_states(ll_head, state_set, *c))
        {
            /* distinguishable state found and splitted, return immediately
             * instead of doing more splits  */
            destroy_generic_list(&trans_chars);
            return 1;
        }
    }

    /* no distinguishable transition/states found */
    destroy_generic_list(&trans_chars);
    return 0;
}

/* Merge undistinguishable states in specified DFA to state sets */
static struct __DFA_state_set *merge_DFA_states(struct DFA_state *dfa)
{
    struct __DFA_state_set *ss = initialize_DFA_state_set(dfa);
    struct __DFA_state_set *cur, *next;
    int changed;

    do {
        changed = 0;
        for (cur = ss->next; cur != ss; cur = next)
        {
            next = cur->next;
            changed += split_state_set(ss, cur);
        }
    } while (changed != 0);

    return ss;
}

/* Make DFA out of specified collection of state sets */
static struct DFA_state *make_optimized_DFA(
    struct __DFA_state_set *head, struct DFA_state *start)
{
    struct __DFA_state_set *cur = head->next, *dest;
    struct DFA_state **cur_state;
    int i_state, n_state;
    int i_trans;
    char trans_char;

    /* allocate DFA state for each merged states */
    for ( ; cur != head; cur = cur->next) {
        cur->merged_state = alloc_DFA_state();
    }

    /* add transitions to these merged states */
    for (cur = head->next ; cur != head; cur = cur->next)
    {
        cur_state = (struct DFA_state **) cur->dfa_states.p_dat;
        n_state   = cur->dfa_states.length;

        for (i_state = 0; i_state < n_state; i_state++, cur_state++)
        {
            for (i_trans = 0; i_trans < (*cur_state)->n_transitions; i_trans++)
            {
                dest = __find_state_set(head, (*cur_state)->trans[i_trans].to);
                trans_char = (*cur_state)->trans[i_trans].trans_char;

                if (DFA_target_of_trans(cur->merged_state, trans_char) == NULL)
                {
                    DFA_add_transition(
                        cur->merged_state, dest->merged_state, trans_char);
                }
            }

            if ((*cur_state)->is_acceptable)
                DFA_make_acceptable(cur->merged_state);
        }
    }

    /* find the start state of the new DFA and return */
    return __find_state_set(head, start)->merged_state;
}

/* Simplify DFA by merging undistinguishable states */
struct DFA_state *DFA_optimize(const struct DFA_state *dfa)
{
    struct DFA_state *_dfa = (struct DFA_state *) dfa;
    struct __DFA_state_set *ss = merge_DFA_states(_dfa);
    struct DFA_state *dfa_opt = make_optimized_DFA(ss, _dfa);
    __destroy_DFA_stateset_list(ss);
    return dfa_opt;
}
/* Destroy the entire DFA */
void DFA_dispose(struct DFA_state *start)
{
    struct generic_list state_list;
    struct DFA_state **cur;
    int i_state = 0;

    create_generic_list(struct DFA_state*, &state_list);
    generic_list_push_back(&state_list, &start);
    DFA_traverse(start, &state_list);

    for (cur = (struct DFA_state**) state_list.p_dat;
         i_state < state_list.length; i_state++, cur++)
    {
        free_DFA_state(*cur);
    }

    destroy_generic_list(&state_list);
}

/* Turn specified DFA state to an acceptable one */
void DFA_make_acceptable(struct DFA_state *state)
{
    state->is_acceptable = 1;
}

/* Add transition between specified DFA states

       /----\  trans_char  /--\
       |from|------------>>|to|
       \----/              \--/
*/
void DFA_add_transition(
    struct DFA_state *from, struct DFA_state *to, char trans_char)
{
    /* If we're running out of space */
    if (from->n_transitions == from->_capacity)
    {
        from->_capacity *= 2;   /* expand two-fold */
        from->trans = (struct DFA_transition*)realloc(
            from->trans, from->_capacity * sizeof(struct DFA_transition));
    }

    /* add transition */
    from->trans[from->n_transitions].to = to;
    from->trans[from->n_transitions].trans_char = trans_char;

    from->n_transitions++;
}

/* Get the target state of specified state under certain transition, if there's
 * no such transition then NULL is returned */
struct DFA_state *DFA_target_of_trans(struct DFA_state *state, char trans_char)
{
    /* we have to iterate through all transitions to find the one we want */
    int i_trans = 0, n_trans = state->n_transitions;

    /* , so here we have to do a bad linear search */
    for ( ; i_trans < n_trans; i_trans++)
    {
        if (state->trans[i_trans].trans_char == trans_char) {
            return state->trans[i_trans].to;  /* transition found */
        }
    }

    return NULL;                /* we haven't found specified transition */
}

/* dump the transitions to *all reachable* states from specified state */
static void __DFA_reachable_states_dump_graphviz(
    const struct DFA_state *state, struct generic_list *visited, FILE *fp)
{
    /* we'll storm down each way (transition) and dump each target state
     * recursively */
    int n_trans = state->n_transitions;
    int i_trans = 0;

    for ( ; i_trans < n_trans; i_trans++)
    {
        /* dump source state and target state, acceptable states are presented
         * as double circles */
        if (state->is_acceptable)   /* source state */
            fprintf(fp,
                "    node [shape = doublecircle label=\"\"]; addr_%p\n",
                (void*)state);      /* target state */

        if (state->trans[i_trans].to->is_acceptable)
            fprintf(fp,
                "    node [shape = doublecircle label=\"\"]; addr_%p\n",
                (void*)state->trans[i_trans].to);

        fprintf(fp, "    node [shape = circle label=\"\"]\n");

        /* if (state->is_acceptable)   /\* source state *\/ */
        /*     fprintf(fp, */
        /*         "    node [shape = doublecircle label=\"%p\"]; addr_%p\n", */
        /*         (void*) state, (void*) state);      /\* target state *\/ */
        /* else */
        /*     fprintf(fp, "    node [shape = circle label=\"%p\"]; addr_%p\n",  */
        /*         (void*) state, (void*) state); */

        /* if (state->trans[i_trans].to->is_acceptable) */
        /*     fprintf(fp, */
        /*         "    node [shape = doublecircle label=\"%p\"]; addr_%p\n", */
        /*         (void*)state->trans[i_trans].to, */
        /*         (void*)state->trans[i_trans].to); */
        /* else */
        /*     fprintf(fp, "    node [shape = circle label=\"%p\"]; addr_%p\n",  */
        /*         (void*)state->trans[i_trans].to, */
        /*         (void*)state->trans[i_trans].to); */

        /* dump the transition from source state and target state */
        fprintf(fp, "    addr_%p -> addr_%p [ label = \"%c\" ]\n",
            (void*) state,
            (void*) state->trans[i_trans].to,
            state->trans[i_trans].trans_char);

        /* dump the successor states of this target state (in recursive
         * fashion) */
        if (generic_list_add(
            visited, &state->trans[i_trans].to, __cmp_addr_DFA_state_ptr) != 0)
        {
            __DFA_reachable_states_dump_graphviz(
                state->trans[i_trans].to, visited, fp);
        }
    }
}

/* Generate DOT code to vizualize the DFA */
void DFA_dump_graphviz_code(const struct DFA_state *start_state, FILE *fp)
{
    struct generic_list visited_state;
    create_generic_list(struct DFA_state *, &visited_state);

    fprintf(fp,
        "digraph finite_state_machine {\n"
        "    rankdir=LR;\n"
        "    size=\"8,5\"\n"
        "    node [shape = circle label=\"\"]\n");

    generic_list_push_back(&visited_state, &start_state);
    __DFA_reachable_states_dump_graphviz(start_state, &visited_state, fp);

    /* dump start mark */
    fprintf(fp, "    node [shape = none label=\"\"]; start\n");
    fprintf(fp, "    start -> addr_%p [ label = \"start\" ]\n", (void*)start_state);

    /* done */
    fprintf(fp, "}\n");
    destroy_generic_list(&visited_state);
}

/* int main(int argc, char *argv[]) */
/* { */
    /* struct NFA nfa; */
    /* struct DFA_state *dfa, *dfa_opt; */

    /* FILE *fp_nfa, *fp_dfa, *fp_dfa_opt; */

    /* if (argc == 2) */
    /* { */
        /* if ( (fp_nfa = fopen("nfa.dot", "w")) == NULL) { */
            /* perror("fopen nfa.dot error"); exit(-1); */
        /* } */
        /* if ( (fp_dfa = fopen("dfa.dot", "w")) == NULL) { */
            /* perror("fopen dfa.dot error"); exit(-1); */
        /* } */
        /* if ( (fp_dfa_opt = fopen("dfa_opt.dot", "w")) == NULL) { */
            /* perror("fopen dfa_opt.dot error"); exit(-1); */
        /* } */

        /* fprintf(stderr, "regexp: %s\n", argv[1]); */

        /* [> parse regexp and generate NFA and DFA <] */
        /* nfa = reg_to_NFA(argv[1]); */
        /* dfa = NFA_to_DFA(&nfa); */
        /* dfa_opt = DFA_optimize(dfa); */

        /* [> dump NFA and DFA as graphviz code <] */
        /* NFA_dump_graphviz_code(&nfa, fp_nfa); */
        /* DFA_dump_graphviz_code(dfa, fp_dfa); */
        /* DFA_dump_graphviz_code(dfa_opt, fp_dfa_opt); */

        /* [> finalize <] */
        /* NFA_dispose(&nfa);    fclose(fp_nfa); */
        /* DFA_dispose(dfa);     fclose(fp_dfa); */
        /* DFA_dispose(dfa_opt); fclose(fp_dfa_opt); */
    /* } */
    /* else { */
        /* printf("usage: %s 'regexp'\n", argv[0]); */
    /* } */

    /* return 0; */
/* } */

struct DFA_state *re2dfa(char *re_string) {
    struct NFA nfa;
    struct DFA_state *dfa, *dfa_opt;

    nfa = reg_to_NFA(re_string);
    dfa = NFA_to_DFA(&nfa);
    dfa_opt = DFA_optimize(dfa);

    return dfa_opt;
}
