/* corpus.h — the evolving set of interesting programs. */
#ifndef XF_CORPUS_H
#define XF_CORPUS_H

#include "prog.h"

typedef struct {
    xf_prog *items;
    uint32_t count;
    uint32_t cap;
} xf_corpus;

void     xf_corpus_init(xf_corpus *c);
void     xf_corpus_free(xf_corpus *c);

/* Deep-copy p into the corpus. */
void     xf_corpus_add(xf_corpus *c, const xf_prog *p);

/* Random member for mutation (NULL if empty). */
const xf_prog *xf_corpus_pick(const xf_corpus *c, xf_rng_t *r);

/* Persist / load the corpus directory (one .prog file per program). */
void     xf_corpus_save(const xf_corpus *c, const char *dir);
uint32_t xf_corpus_load(xf_corpus *c, const char *dir);

/* Write a single program to <dir>/<tag>.prog (used for crashes/seeds). */
void     xf_corpus_write_one(const xf_prog *p, const char *dir, const char *tag);

/* ----- coverage-lite novelty oracle -------------------------------------- *
 * Without KCOV we approximate "new behaviour" with a set of 64-bit execution
 * signatures (call sequence + observed status). A program with a fresh
 * signature is deemed interesting and retained. */
bool     xf_novelty_seen(uint64_t sig);   /* true if already recorded        */
uint64_t xf_prog_signature(const xf_prog *p, int status, int signo);

#endif /* XF_CORPUS_H */
