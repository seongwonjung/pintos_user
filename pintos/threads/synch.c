/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */

// 2️⃣ 대기자 정렬(내림차순)
static bool waiter_cmp_priority (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED){
	const struct thread *ta = list_entry(a, struct thread, elem);
    const struct thread *tb = list_entry(b, struct thread, elem);
    return ta->priority > tb->priority;                       /* 내림차순(큰 priority가 앞) */
}

void
sema_init (struct semaphore *sema, unsigned value) {
	ASSERT (sema != NULL);

	sema->value = value;
	list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */

// 2️⃣ 정렬 삽입
void sema_down (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);
	ASSERT (!intr_context ());

	old_level = intr_disable ();                           // 인터럽트 OFF
	while (sema->value == 0) {
		// list_push_back (&sema->waiters, &thread_current ()->elem);   // FIFO
		list_insert_ordered(&sema->waiters, &thread_current()->elem, waiter_cmp_priority, NULL);  // 3️⃣ 대기열에 현재 스레드를 '우선순위 내림차순'으로 삽입
		thread_block ();                                     // 현재 스레드 Block
	}
	sema->value--;                                           // 티켓 1개 감소
	intr_set_level (old_level);                              // 인터럽트 ON
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) {
	enum intr_level old_level;
	bool success;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level (old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */

// 2️⃣ 최고 우선순위 선점시키기
void sema_up (struct semaphore *sema) {
	enum intr_level old_level;                      // 인터럽트 상태 저장
	struct thread *to_unblock = NULL;              // 2️⃣ 깨울 대상 스레드 포인터
    bool need_yield = false;                       // 2️⃣ CPU를 양보할지 여부를 기록할 플래그

	ASSERT (sema != NULL);                          // 방어 코드

	old_level = intr_disable ();                     // 인터럽트 OFF

	if (!list_empty (&sema->waiters)){
		list_sort(&sema->waiters, waiter_cmp_priority, NULL);                               // 안전 장치(한 번 더 정렬)
		to_unblock = list_entry(list_pop_front(&sema->waiters), struct thread, elem);      // 2️⃣ 맨 앞(=최고 우선순위) 대기자를 꺼냄(pop) 

		thread_unblock(to_unblock);                                                        // READY 상태로 전환

		if (to_unblock->priority > thread_current()->priority) {                           // 방금 깨운 스레드가 지급보다 우선순위가 높으면 → 선점 필요
			if (intr_context()) intr_yield_on_return();                                    // IF, 인터럽트 핸들러 안 -> 이번 인터럽트 리턴(처리 끝나고 원래 스레드로 돌아가기 직전) 때 yield 해라
            else  need_yield = true;                                                       // 그 외(일반 스레드 컨텍스트) ->  나중에 양보하도록 플래그만 세움 ✔️

		// 	thread_unblock (list_entry (list_pop_front (&sema->waiters),struct thread, elem));
	    // sema->value++;
	    // intr_set_level (old_level);
        }
    }
	sema->value++;                               // 세마포어 값 증가(티켓 반납)
	intr_set_level(old_level);                   // 인터럽트 ON

	if (need_yield) thread_yield();             // 2️⃣ 인터럽트가 켜진 뒤에 실제로 CPU를 양보 ✔️
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) {
	struct semaphore sema[2];
	int i;

	printf ("Testing semaphores...");
	sema_init (&sema[0], 0);
	sema_init (&sema[1], 0);
	thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up (&sema[0]);
		sema_down (&sema[1]);
	}
	printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) {
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down (&sema[0]);
		sema_up (&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock) {
	ASSERT (lock != NULL);

	lock->holder = NULL;
	sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void lock_acquire (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (!lock_held_by_current_thread (lock));

   // 3️⃣ Donation(multiple)
   struct thread *cur = thread_current();               // 현재 스레드(이후 모든 변경 기준)

   if (lock->holder != NULL) {                          /* 경합: 누군가 들고 있음 */
    enum intr_level old = intr_disable();
    cur->waiting_lock = lock;                           /* (nest) 전파 경로의 시작점 기록 */
    list_push_back(&lock->holder->donations, &cur->donation_elem);       /* 락 보유자(holder)의 donations 리스트에 **나(cur)**를 추가 */
                  
    thread_refresh_priority(lock->holder);              /* 홀더의 유효 priority 갱신(최댓값 반영) */
    intr_set_level(old);

    thread_donate_chain(cur);                           /* (nest) waiting_lock 체인을 따라 상류로 연쇄 갱신 */
    
    
    thread_yield_if_lower();                          /* ★ 중요: donation으로 READY 최상단이 바뀌었을 수 있으므로 즉시 선점 검사 */
   
   // 3️⃣ donate-one: 락 홀더가 있고, 내가 더 높으면 홀더에게 기부
   // if (lock->holder != NULL) {
   //    struct thread *cur = thread_current();
   //    struct thread *holder = lock->holder;
   //    if (cur->priority > holder->priority) {
   //      enum intr_level old = intr_disable();
   //      holder->priority = cur->priority;      // 1단계 도네이션(donate-one)
   //      intr_set_level(old);
   //  }
  }

  sema_down (&lock->semaphore);                         /* 실제로 획득될 때까지 대기 */
  enum intr_level old2 = intr_disable();
  cur->waiting_lock = NULL;                             /* 더 이상 이 락을 기다리지 않음 */
  lock->holder = cur;                                   /* 소유권 이전 */
  intr_set_level(old2);
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock) {
	bool success;

	ASSERT (lock != NULL);
	ASSERT (!lock_held_by_current_thread (lock));

	success = sema_try_down (&lock->semaphore);
	if (success)
		lock->holder = thread_current ();
	return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void lock_release (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (lock_held_by_current_thread (lock));

	// lock->holder = NULL;

   //3️⃣ 기부 해제: 내 우선순위를 원래 값(base_priority)으로 복원 
   enum intr_level old = intr_disable();
   thread_remove_donations_with_lock(lock);              /* (multiple1) 이 락에서 비롯된 기부만 제거 */
   thread_refresh_priority(thread_current());            /* 유효 priority 재계산: max(base_priority, 남아있는 기부 최댓값) */
   // thread_current()->priority = thread_current()->base_priority;

   lock->holder = NULL;        // 락 소유권 해제
   intr_set_level(old);

	sema_up (&lock->semaphore);                            // 가장 높은 대기자 깨우기
   thread_yield_if_lower();                              /* 필요하면 즉시 양보(선점 보장) */
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) {
	ASSERT (lock != NULL);

	return lock->holder == thread_current ();
}

/* One semaphore in a list. */
struct semaphore_elem {
	struct list_elem elem;              /* List element. */
	struct semaphore semaphore;         /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond) {
	ASSERT (cond != NULL);

	list_init (&cond->waiters);
}

// 2️⃣ condvar 정렬
static bool cond_sema_cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED) {
  struct semaphore_elem *sa = list_entry(a, struct semaphore_elem, elem);
  struct semaphore_elem *sb = list_entry(b, struct semaphore_elem, elem);

  // 각 세마포어의 waiters 맨 앞(thread)의 priority 비교
  struct thread *ta = list_entry(list_front(&sa->semaphore.waiters), struct thread, elem);
  struct thread *tb = list_entry(list_front(&sb->semaphore.waiters), struct thread, elem);

  return ta->priority > tb->priority;  // 내림차순
}


/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock) {
	struct semaphore_elem waiter;

	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	sema_init (&waiter.semaphore, 0);
	list_push_back (&cond->waiters, &waiter.elem);
	lock_release (lock);
	sema_down (&waiter.semaphore);
	lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	// 2️⃣ condvar
	if (!list_empty (&cond->waiters)){
		// sema_up (&list_entry (list_pop_front (&cond->waiters), struct semaphore_elem, elem)->semaphore);
        list_sort(&cond->waiters, cond_sema_cmp_priority, NULL);                                                // (1) cond->waiters를 “각 세마가 깨울 최고 우선순위 스레드” 기준으로 정렬

        struct semaphore_elem *se = list_entry(list_pop_front(&cond->waiters), struct semaphore_elem, elem);    // (2) 맨 앞(= 가장 높은 우선순위를 깨울 수 있는 세마)을 꺼내고

        sema_up(&se->semaphore);   //// (3) 그 세마를 올려서(sema_up) 해당 스레드를 깨움
  }
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);

	while (!list_empty (&cond->waiters))
		cond_signal (cond, lock);
}