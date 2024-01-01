#include <kunit/test.h>
#include <linux/tipc.h>
#include "crypto.h"


int tipc_crypto_start_test(struct kunit *test, struct tipc_crypto **crypto, struct net *net,
		      struct tipc_node *node)
{
	struct tipc_crypto *c;

	if (*crypto)
		return -EEXIST;
	/* Allocate crypto */
	c = kunit_kzalloc(test, sizeof(*c), GFP_ATOMIC);
	if (!c)
		return -ENOMEM;
	/* Allocate workqueue on TX */
	if (!node) {
		c->wq = alloc_ordered_workqueue("tipc_crypto", 0);
		if (!c->wq) {
			kfree(c);
			return -ENOMEM;
		}
	}

	/* Allocate statistic structure */
	c->stats = alloc_percpu_gfp(struct tipc_crypto_stats, GFP_ATOMIC);
	if (!c->stats) {
		if (c->wq)
			destroy_workqueue(c->wq);
		kfree_sensitive(c);
		return -ENOMEM;
	}

	c->flags = 0;
	c->net = net;
	c->node = node;
	get_random_bytes(&c->key_gen, 2);
	tipc_crypto_key_set_state(c, 0, 0, 0);
	atomic_set(&c->key_distr, 0);
	atomic_set(&c->peer_rx_active, 0);
	atomic64_set(&c->sndnxt, 0);
	c->timer1 = jiffies;
	c->timer2 = jiffies;
	c->rekeying_intv = TIPC_REKEYING_INTV_DEF;
	spin_lock_init(&c->lock);

	scnprintf(c->name, 48, "TIPC_TEST");

	*crypto = c;

	return 0;
}

static void tipc_crypto_key_rcv_test(struct kunit *test) {

  struct tipc_crypto *rx;
  struct tipc_msg msg;
  uint32_t *keylen_p;
  uint32_t *key_p;

  u8 *data;
  u8 *data_too;
  rx = NULL;

  int tipc_cryp_status = tipc_crypto_start_test(test, &rx, NULL, NULL);
  KUNIT_ASSERT_EQ(test, tipc_cryp_status, 0);
  
  data = kunit_kzalloc(test, 64, GFP_ATOMIC);

  strcpy(data, "AIXCC_ROX"); // Algorithm name
  keylen_p = (uint32_t*)(data + TIPC_AEAD_ALG_NAME);
  *keylen_p = htonl(20);
  key_p = (uint32_t*)(data + TIPC_AEAD_ALG_NAME + sizeof(__be32));
  memcpy(key_p, "0123456789",10);
 

  msg_set_key_gen(&msg, 15);
  msg_set_size(&msg, 60);
  msg_set_hdr_sz(&msg, 5);
  data_too = msg_data(&msg);
  memcpy(data_too, data, 50);

  KUNIT_ASSERT_EQ(test, (long)rx->skey, 0);
  bool res = tipc_crypto_key_rcv(rx, &msg);

  KUNIT_ASSERT_FALSE(test, res);
  KUNIT_ASSERT_STREQ(test, rx->skey->alg_name, "AIXCC_ROX");
  KUNIT_ASSERT_TRUE(test, !memcmp(key_p, rx->skey->key,10));

  tipc_crypto_stop(&rx);
}
static struct kunit_case example_test_cases[] = {
	KUNIT_CASE(tipc_crypto_key_rcv_test),
	{}
};

static struct kunit_suite misc_example_test_suite = {
	.name = "tipc-example",
	.test_cases = example_test_cases,
};

kunit_test_suite(misc_example_test_suite); 

MODULE_LICENSE("GPL");
