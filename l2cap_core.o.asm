
l2cap_core.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <__l2cap_global_chan_by_addr>:
	}
	return NULL;
}

static struct l2cap_chan *__l2cap_global_chan_by_addr(__le16 psm, bdaddr_t *src)
{
       0:	55                   	push   %rbp
       1:	48 89 e5             	mov    %rsp,%rbp
       4:	41 55                	push   %r13
       6:	41 54                	push   %r12
       8:	53                   	push   %rbx
       9:	48 83 ec 08          	sub    $0x8,%rsp
       d:	e8 00 00 00 00       	callq  12 <__l2cap_global_chan_by_addr+0x12>
	struct l2cap_chan *c;

	list_for_each_entry(c, &chan_list, global_l) {
      12:	48 8b 05 00 00 00 00 	mov    0x0(%rip),%rax        # 19 <__l2cap_global_chan_by_addr+0x19>
{
      19:	49 89 f5             	mov    %rsi,%r13
      1c:	41 89 fc             	mov    %edi,%r12d
	list_for_each_entry(c, &chan_list, global_l) {
      1f:	48 3d 00 00 00 00    	cmp    $0x0,%rax
      25:	48 8d 98 d8 fc ff ff 	lea    -0x328(%rax),%rbx
      2c:	75 18                	jne    46 <__l2cap_global_chan_by_addr+0x46>
      2e:	eb 50                	jmp    80 <__l2cap_global_chan_by_addr+0x80>
      30:	48 8b 83 28 03 00 00 	mov    0x328(%rbx),%rax
      37:	48 3d 00 00 00 00    	cmp    $0x0,%rax
      3d:	48 8d 98 d8 fc ff ff 	lea    -0x328(%rax),%rbx
      44:	74 3a                	je     80 <__l2cap_global_chan_by_addr+0x80>
		if (c->sport == psm && !bacmp(&bt_sk(c->sk)->src, src))
      46:	66 44 39 63 28       	cmp    %r12w,0x28(%rbx)
      4b:	75 e3                	jne    30 <__l2cap_global_chan_by_addr+0x30>
#define BDADDR_LOCAL (&(bdaddr_t) {{0, 0, 0, 0xff, 0xff, 0xff}})

/* Copy, swap, convert BD Address */
static inline int bacmp(bdaddr_t *ba1, bdaddr_t *ba2)
{
	return memcmp(ba1, ba2, sizeof(bdaddr_t));
      4d:	48 8b 03             	mov    (%rbx),%rax
      50:	ba 06 00 00 00       	mov    $0x6,%edx
      55:	4c 89 ee             	mov    %r13,%rsi
      58:	48 8d b8 88 02 00 00 	lea    0x288(%rax),%rdi
      5f:	e8 00 00 00 00       	callq  64 <__l2cap_global_chan_by_addr+0x64>
      64:	85 c0                	test   %eax,%eax
      66:	75 c8                	jne    30 <__l2cap_global_chan_by_addr+0x30>
			return c;
	}
	return NULL;
}
      68:	48 83 c4 08          	add    $0x8,%rsp
      6c:	48 89 d8             	mov    %rbx,%rax
      6f:	5b                   	pop    %rbx
      70:	41 5c                	pop    %r12
      72:	41 5d                	pop    %r13
      74:	5d                   	pop    %rbp
      75:	c3                   	retq   
      76:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
      7d:	00 00 00 
      80:	48 83 c4 08          	add    $0x8,%rsp
	return NULL;
      84:	31 c0                	xor    %eax,%eax
}
      86:	5b                   	pop    %rbx
      87:	41 5c                	pop    %r12
      89:	41 5d                	pop    %r13
      8b:	5d                   	pop    %rbp
      8c:	c3                   	retq   
      8d:	0f 1f 00             	nopl   (%rax)

0000000000000090 <__l2cap_state_change>:

	return 0;
}

static void __l2cap_state_change(struct l2cap_chan *chan, int state)
{
      90:	55                   	push   %rbp
      91:	48 89 e5             	mov    %rsp,%rbp
      94:	41 54                	push   %r12
      96:	53                   	push   %rbx
      97:	e8 00 00 00 00       	callq  9c <__l2cap_state_change+0xc>
	BT_DBG("chan %p %s -> %s", chan, state_to_string(chan->state),
      9c:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # a3 <__l2cap_state_change+0x13>
{
      a3:	48 89 fb             	mov    %rdi,%rbx
      a6:	41 89 f4             	mov    %esi,%r12d
	BT_DBG("chan %p %s -> %s", chan, state_to_string(chan->state),
      a9:	75 1d                	jne    c8 <__l2cap_state_change+0x38>
						state_to_string(state));

	chan->state = state;
	chan->ops->state_change(chan->data, state);
      ab:	48 8b 83 40 03 00 00 	mov    0x340(%rbx),%rax
	chan->state = state;
      b2:	44 88 63 10          	mov    %r12b,0x10(%rbx)
	chan->ops->state_change(chan->data, state);
      b6:	44 89 e6             	mov    %r12d,%esi
      b9:	48 8b bb 38 03 00 00 	mov    0x338(%rbx),%rdi
      c0:	ff 50 20             	callq  *0x20(%rax)
}
      c3:	5b                   	pop    %rbx
      c4:	41 5c                	pop    %r12
      c6:	5d                   	pop    %rbp
      c7:	c3                   	retq   
      c8:	8d 46 ff             	lea    -0x1(%rsi),%eax
	switch (state) {
      cb:	49 c7 c0 00 00 00 00 	mov    $0x0,%r8
      d2:	83 f8 08             	cmp    $0x8,%eax
      d5:	77 08                	ja     df <__l2cap_state_change+0x4f>
      d7:	4c 8b 04 c5 00 00 00 	mov    0x0(,%rax,8),%r8
      de:	00 
      df:	0f b6 43 10          	movzbl 0x10(%rbx),%eax
      e3:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
      ea:	83 e8 01             	sub    $0x1,%eax
      ed:	83 f8 08             	cmp    $0x8,%eax
      f0:	77 08                	ja     fa <__l2cap_state_change+0x6a>
      f2:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
      f9:	00 
	BT_DBG("chan %p %s -> %s", chan, state_to_string(chan->state),
      fa:	48 89 da             	mov    %rbx,%rdx
      fd:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
     104:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
     10b:	31 c0                	xor    %eax,%eax
     10d:	e8 00 00 00 00       	callq  112 <__l2cap_state_change+0x82>
     112:	eb 97                	jmp    ab <__l2cap_state_change+0x1b>
     114:	66 90                	xchg   %ax,%ax
     116:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
     11d:	00 00 00 

0000000000000120 <l2cap_build_conf_rsp>:

	return ptr - data;
}

static int l2cap_build_conf_rsp(struct l2cap_chan *chan, void *data, u16 result, u16 flags)
{
     120:	55                   	push   %rbp
     121:	48 89 e5             	mov    %rsp,%rbp
     124:	41 55                	push   %r13
     126:	41 54                	push   %r12
     128:	53                   	push   %rbx
     129:	48 83 ec 18          	sub    $0x18,%rsp
     12d:	e8 00 00 00 00       	callq  132 <l2cap_build_conf_rsp+0x12>
	struct l2cap_conf_rsp *rsp = data;
	void *ptr = rsp->data;

	BT_DBG("chan %p", chan);
     132:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 139 <l2cap_build_conf_rsp+0x19>
{
     139:	49 89 fc             	mov    %rdi,%r12
     13c:	48 89 f3             	mov    %rsi,%rbx
     13f:	41 89 d5             	mov    %edx,%r13d
	BT_DBG("chan %p", chan);
     142:	75 22                	jne    166 <l2cap_build_conf_rsp+0x46>

	rsp->scid   = cpu_to_le16(chan->dcid);
     144:	41 0f b7 44 24 1a    	movzwl 0x1a(%r12),%eax
	rsp->result = cpu_to_le16(result);
     14a:	66 44 89 6b 04       	mov    %r13w,0x4(%rbx)
	rsp->flags  = cpu_to_le16(flags);
     14f:	66 89 4b 02          	mov    %cx,0x2(%rbx)
	rsp->scid   = cpu_to_le16(chan->dcid);
     153:	66 89 03             	mov    %ax,(%rbx)

	return ptr - data;
}
     156:	48 83 c4 18          	add    $0x18,%rsp
     15a:	b8 06 00 00 00       	mov    $0x6,%eax
     15f:	5b                   	pop    %rbx
     160:	41 5c                	pop    %r12
     162:	41 5d                	pop    %r13
     164:	5d                   	pop    %rbp
     165:	c3                   	retq   
	BT_DBG("chan %p", chan);
     166:	48 89 fa             	mov    %rdi,%rdx
     169:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
     170:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
     177:	31 c0                	xor    %eax,%eax
     179:	89 4d dc             	mov    %ecx,-0x24(%rbp)
     17c:	e8 00 00 00 00       	callq  181 <l2cap_build_conf_rsp+0x61>
     181:	8b 4d dc             	mov    -0x24(%rbp),%ecx
     184:	eb be                	jmp    144 <l2cap_build_conf_rsp+0x24>
     186:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
     18d:	00 00 00 

0000000000000190 <l2cap_get_chan_by_scid>:
{
     190:	55                   	push   %rbp
     191:	48 89 e5             	mov    %rsp,%rbp
     194:	41 57                	push   %r15
     196:	41 56                	push   %r14
     198:	41 55                	push   %r13
     19a:	41 54                	push   %r12
     19c:	53                   	push   %rbx
     19d:	48 83 ec 08          	sub    $0x8,%rsp
     1a1:	e8 00 00 00 00       	callq  1a6 <l2cap_get_chan_by_scid+0x16>
	mutex_lock(&conn->chan_lock);
     1a6:	4c 8d af 40 01 00 00 	lea    0x140(%rdi),%r13
{
     1ad:	49 89 fe             	mov    %rdi,%r14
     1b0:	41 89 f7             	mov    %esi,%r15d
     1b3:	41 89 f4             	mov    %esi,%r12d
	mutex_lock(&conn->chan_lock);
     1b6:	4c 89 ef             	mov    %r13,%rdi
     1b9:	e8 00 00 00 00       	callq  1be <l2cap_get_chan_by_scid+0x2e>
	list_for_each_entry(c, &conn->chan_l, list) {
     1be:	49 8b 96 30 01 00 00 	mov    0x130(%r14),%rdx
     1c5:	49 8d 86 30 01 00 00 	lea    0x130(%r14),%rax
     1cc:	48 39 d0             	cmp    %rdx,%rax
     1cf:	48 8d 9a e8 fc ff ff 	lea    -0x318(%rdx),%rbx
     1d6:	74 2d                	je     205 <l2cap_get_chan_by_scid+0x75>
		if (c->scid == cid)
     1d8:	66 44 3b ba 04 fd ff 	cmp    -0x2fc(%rdx),%r15w
     1df:	ff 
     1e0:	75 10                	jne    1f2 <l2cap_get_chan_by_scid+0x62>
     1e2:	eb 44                	jmp    228 <l2cap_get_chan_by_scid+0x98>
     1e4:	0f 1f 40 00          	nopl   0x0(%rax)
     1e8:	66 44 3b a2 04 fd ff 	cmp    -0x2fc(%rdx),%r12w
     1ef:	ff 
     1f0:	74 36                	je     228 <l2cap_get_chan_by_scid+0x98>
	list_for_each_entry(c, &conn->chan_l, list) {
     1f2:	48 8b 93 18 03 00 00 	mov    0x318(%rbx),%rdx
     1f9:	48 39 d0             	cmp    %rdx,%rax
     1fc:	48 8d 9a e8 fc ff ff 	lea    -0x318(%rdx),%rbx
     203:	75 e3                	jne    1e8 <l2cap_get_chan_by_scid+0x58>
     205:	31 db                	xor    %ebx,%ebx
	mutex_unlock(&conn->chan_lock);
     207:	4c 89 ef             	mov    %r13,%rdi
     20a:	e8 00 00 00 00       	callq  20f <l2cap_get_chan_by_scid+0x7f>
}
     20f:	48 83 c4 08          	add    $0x8,%rsp
     213:	48 89 d8             	mov    %rbx,%rax
     216:	5b                   	pop    %rbx
     217:	41 5c                	pop    %r12
     219:	41 5d                	pop    %r13
     21b:	41 5e                	pop    %r14
     21d:	41 5f                	pop    %r15
     21f:	5d                   	pop    %rbp
     220:	c3                   	retq   
     221:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
	if (c)
     228:	48 85 db             	test   %rbx,%rbx
     22b:	74 d8                	je     205 <l2cap_get_chan_by_scid+0x75>
		kfree(c);
}

static inline void l2cap_chan_lock(struct l2cap_chan *chan)
{
	mutex_lock(&chan->lock);
     22d:	48 8d bb 48 03 00 00 	lea    0x348(%rbx),%rdi
     234:	e8 00 00 00 00       	callq  239 <l2cap_get_chan_by_scid+0xa9>
     239:	eb cc                	jmp    207 <l2cap_get_chan_by_scid+0x77>
     23b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000000240 <l2cap_seq_list_init>:
{
     240:	55                   	push   %rbp
     241:	48 89 e5             	mov    %rsp,%rbp
     244:	41 55                	push   %r13
     246:	41 54                	push   %r12
     248:	53                   	push   %rbx
     249:	48 83 ec 08          	sub    $0x8,%rsp
     24d:	e8 00 00 00 00       	callq  252 <l2cap_seq_list_init+0x12>
	/*
	 * AMD64 says BSRQ won't clobber the dest reg if x==0; Intel64 says the
	 * dest reg is undefined if x==0, but their CPU architect says its
	 * value is written to set it to the same as before.
	 */
	asm("bsrq %1,%0"
     252:	49 c7 c5 ff ff ff ff 	mov    $0xffffffffffffffff,%r13
 * round up to nearest power of two
 */
static inline __attribute__((const))
unsigned long __roundup_pow_of_two(unsigned long n)
{
	return 1UL << fls_long(n - 1);
     259:	bb 01 00 00 00       	mov    $0x1,%ebx
	alloc_size = roundup_pow_of_two(size);
     25e:	0f b7 f6             	movzwl %si,%esi
     261:	4c 89 e9             	mov    %r13,%rcx
{
     264:	49 89 fc             	mov    %rdi,%r12
     267:	48 83 ee 01          	sub    $0x1,%rsi
     26b:	48 0f bd ce          	bsr    %rsi,%rcx
	    : "+r" (bitpos)
	    : "rm" (x));
	return bitpos + 1;
     26f:	83 c1 01             	add    $0x1,%ecx
				return ZERO_SIZE_PTR;

			return kmem_cache_alloc_trace(s, flags, size);
		}
	}
	return __kmalloc(size, flags);
     272:	be d0 00 00 00       	mov    $0xd0,%esi
     277:	48 d3 e3             	shl    %cl,%rbx
	seq_list->list = kmalloc(sizeof(u16) * alloc_size, GFP_KERNEL);
     27a:	48 8d 3c 1b          	lea    (%rbx,%rbx,1),%rdi
     27e:	e8 00 00 00 00       	callq  283 <l2cap_seq_list_init+0x43>
	if (!seq_list->list)
     283:	48 85 c0             	test   %rax,%rax
	seq_list->list = kmalloc(sizeof(u16) * alloc_size, GFP_KERNEL);
     286:	49 89 44 24 08       	mov    %rax,0x8(%r12)
	if (!seq_list->list)
     28b:	74 47                	je     2d4 <l2cap_seq_list_init+0x94>
	seq_list->mask = alloc_size - 1;
     28d:	8d 53 ff             	lea    -0x1(%rbx),%edx
	seq_list->head = L2CAP_SEQ_LIST_CLEAR;
     290:	66 45 89 2c 24       	mov    %r13w,(%r12)
	seq_list->tail = L2CAP_SEQ_LIST_CLEAR;
     295:	66 45 89 6c 24 02    	mov    %r13w,0x2(%r12)
	seq_list->mask = alloc_size - 1;
     29b:	66 41 89 54 24 04    	mov    %dx,0x4(%r12)
	for (i = 0; i < alloc_size; i++)
     2a1:	31 d2                	xor    %edx,%edx
     2a3:	48 85 db             	test   %rbx,%rbx
     2a6:	75 0d                	jne    2b5 <l2cap_seq_list_init+0x75>
     2a8:	eb 1d                	jmp    2c7 <l2cap_seq_list_init+0x87>
     2aa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
     2b0:	49 8b 44 24 08       	mov    0x8(%r12),%rax
		seq_list->list[i] = L2CAP_SEQ_LIST_CLEAR;
     2b5:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
     2ba:	66 89 0c 50          	mov    %cx,(%rax,%rdx,2)
	for (i = 0; i < alloc_size; i++)
     2be:	48 83 c2 01          	add    $0x1,%rdx
     2c2:	48 39 da             	cmp    %rbx,%rdx
     2c5:	75 e9                	jne    2b0 <l2cap_seq_list_init+0x70>
	return 0;
     2c7:	31 c0                	xor    %eax,%eax
}
     2c9:	48 83 c4 08          	add    $0x8,%rsp
     2cd:	5b                   	pop    %rbx
     2ce:	41 5c                	pop    %r12
     2d0:	41 5d                	pop    %r13
     2d2:	5d                   	pop    %rbp
     2d3:	c3                   	retq   
		return -ENOMEM;
     2d4:	b8 f4 ff ff ff       	mov    $0xfffffff4,%eax
     2d9:	eb ee                	jmp    2c9 <l2cap_seq_list_init+0x89>
     2db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000002e0 <__l2cap_chan_add>:
{
     2e0:	55                   	push   %rbp
     2e1:	48 89 e5             	mov    %rsp,%rbp
     2e4:	41 54                	push   %r12
     2e6:	53                   	push   %rbx
     2e7:	e8 00 00 00 00       	callq  2ec <__l2cap_chan_add+0xc>
	BT_DBG("conn %p, psm 0x%2.2x, dcid 0x%4.4x", conn,
     2ec:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 2f3 <__l2cap_chan_add+0x13>
{
     2f3:	49 89 fc             	mov    %rdi,%r12
     2f6:	48 89 f3             	mov    %rsi,%rbx
	BT_DBG("conn %p, psm 0x%2.2x, dcid 0x%4.4x", conn,
     2f9:	0f 85 8a 01 00 00    	jne    489 <__l2cap_chan_add+0x1a9>
	conn->disc_reason = HCI_ERROR_REMOTE_USER_TERM;
     2ff:	41 c6 84 24 b5 00 00 	movb   $0x13,0xb5(%r12)
     306:	00 13 
	switch (chan->chan_type) {
     308:	0f b6 43 25          	movzbl 0x25(%rbx),%eax
	chan->conn = conn;
     30c:	4c 89 63 08          	mov    %r12,0x8(%rbx)
	switch (chan->chan_type) {
     310:	3c 02                	cmp    $0x2,%al
     312:	0f 84 13 01 00 00    	je     42b <__l2cap_chan_add+0x14b>
     318:	3c 03                	cmp    $0x3,%al
     31a:	75 46                	jne    362 <__l2cap_chan_add+0x82>
		if (conn->hcon->type == LE_LINK) {
     31c:	49 8b 04 24          	mov    (%r12),%rax
     320:	80 78 21 80          	cmpb   $0x80,0x21(%rax)
     324:	0f 84 35 01 00 00    	je     45f <__l2cap_chan_add+0x17f>
     32a:	49 8b 94 24 30 01 00 	mov    0x130(%r12),%rdx
     331:	00 
     332:	49 8d b4 24 30 01 00 	lea    0x130(%r12),%rsi
     339:	00 
	list_for_each_entry(c, &conn->chan_l, list) {
     33a:	41 b8 40 00 00 00    	mov    $0x40,%r8d
     340:	48 39 d6             	cmp    %rdx,%rsi
     343:	48 8d ba e8 fc ff ff 	lea    -0x318(%rdx),%rdi
     34a:	0f 85 a4 00 00 00    	jne    3f4 <__l2cap_chan_add+0x114>
			chan->omtu = L2CAP_DEFAULT_MTU;
     350:	41 ba a0 02 00 00    	mov    $0x2a0,%r10d
			chan->scid = l2cap_alloc_cid(conn);
     356:	66 44 89 43 1c       	mov    %r8w,0x1c(%rbx)
			chan->omtu = L2CAP_DEFAULT_MTU;
     35b:	66 44 89 53 20       	mov    %r10w,0x20(%rbx)
     360:	eb 23                	jmp    385 <__l2cap_chan_add+0xa5>
		chan->omtu = L2CAP_DEFAULT_MTU;
     362:	be a0 02 00 00       	mov    $0x2a0,%esi
		chan->scid = L2CAP_CID_SIGNALING;
     367:	ba 01 00 00 00       	mov    $0x1,%edx
		chan->dcid = L2CAP_CID_SIGNALING;
     36c:	b9 01 00 00 00       	mov    $0x1,%ecx
		chan->omtu = L2CAP_DEFAULT_MTU;
     371:	66 89 73 20          	mov    %si,0x20(%rbx)
     375:	49 8d b4 24 30 01 00 	lea    0x130(%r12),%rsi
     37c:	00 
		chan->scid = L2CAP_CID_SIGNALING;
     37d:	66 89 53 1c          	mov    %dx,0x1c(%rbx)
		chan->dcid = L2CAP_CID_SIGNALING;
     381:	66 89 4b 1a          	mov    %cx,0x1a(%rbx)
	chan->local_msdu	= L2CAP_DEFAULT_MAX_SDU_SIZE;
     385:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
	chan->local_id		= L2CAP_BESTEFFORT_ID;
     38a:	c6 83 ce 00 00 00 01 	movb   $0x1,0xce(%rbx)
	chan->local_stype	= L2CAP_SERV_BESTEFFORT;
     391:	c6 83 cf 00 00 00 01 	movb   $0x1,0xcf(%rbx)
	chan->local_msdu	= L2CAP_DEFAULT_MAX_SDU_SIZE;
     398:	66 89 83 d0 00 00 00 	mov    %ax,0xd0(%rbx)
	chan->local_sdu_itime	= L2CAP_DEFAULT_SDU_ITIME;
     39f:	c7 83 d4 00 00 00 ff 	movl   $0xffffffff,0xd4(%rbx)
     3a6:	ff ff ff 
	chan->local_acc_lat	= L2CAP_DEFAULT_ACC_LAT;
     3a9:	c7 83 d8 00 00 00 ff 	movl   $0xffffffff,0xd8(%rbx)
     3b0:	ff ff ff 
	chan->local_flush_to	= L2CAP_DEFAULT_FLUSH_TO;
     3b3:	c7 83 dc 00 00 00 ff 	movl   $0xffff,0xdc(%rbx)
     3ba:	ff 00 00 
 *
 * Atomically increments @v by 1.
 */
static inline void atomic_inc(atomic_t *v)
{
	asm volatile(LOCK_PREFIX "incl %0"
     3bd:	f0 ff 43 14          	lock incl 0x14(%rbx)
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
     3c1:	49 8b 94 24 30 01 00 	mov    0x130(%r12),%rdx
     3c8:	00 
	list_add(&chan->list, &conn->chan_l);
     3c9:	48 8d bb 18 03 00 00 	lea    0x318(%rbx),%rdi
     3d0:	e8 00 00 00 00       	callq  3d5 <__l2cap_chan_add+0xf5>
}
     3d5:	5b                   	pop    %rbx
     3d6:	41 5c                	pop    %r12
     3d8:	5d                   	pop    %rbp
     3d9:	c3                   	retq   
     3da:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		if (!__l2cap_get_chan_by_scid(conn, cid))
     3e0:	48 85 c9             	test   %rcx,%rcx
     3e3:	0f 84 67 ff ff ff    	je     350 <__l2cap_chan_add+0x70>
	for (; cid < L2CAP_CID_DYN_END; cid++) {
     3e9:	41 83 c0 01          	add    $0x1,%r8d
     3ed:	66 41 83 f8 ff       	cmp    $0xffff,%r8w
     3f2:	74 63                	je     457 <__l2cap_chan_add+0x177>
		if (c->scid == cid)
     3f4:	66 44 39 82 04 fd ff 	cmp    %r8w,-0x2fc(%rdx)
     3fb:	ff 
	list_for_each_entry(c, &conn->chan_l, list) {
     3fc:	48 89 f9             	mov    %rdi,%rcx
		if (c->scid == cid)
     3ff:	74 df                	je     3e0 <__l2cap_chan_add+0x100>
     401:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
	list_for_each_entry(c, &conn->chan_l, list) {
     408:	48 8b 81 18 03 00 00 	mov    0x318(%rcx),%rax
     40f:	48 39 c6             	cmp    %rax,%rsi
     412:	48 8d 88 e8 fc ff ff 	lea    -0x318(%rax),%rcx
     419:	0f 84 31 ff ff ff    	je     350 <__l2cap_chan_add+0x70>
		if (c->scid == cid)
     41f:	66 44 39 80 04 fd ff 	cmp    %r8w,-0x2fc(%rax)
     426:	ff 
     427:	75 df                	jne    408 <__l2cap_chan_add+0x128>
     429:	eb b5                	jmp    3e0 <__l2cap_chan_add+0x100>
		chan->scid = L2CAP_CID_CONN_LESS;
     42b:	bf 02 00 00 00       	mov    $0x2,%edi
		chan->dcid = L2CAP_CID_CONN_LESS;
     430:	41 b8 02 00 00 00    	mov    $0x2,%r8d
		chan->omtu = L2CAP_DEFAULT_MTU;
     436:	41 b9 a0 02 00 00    	mov    $0x2a0,%r9d
		chan->scid = L2CAP_CID_CONN_LESS;
     43c:	66 89 7b 1c          	mov    %di,0x1c(%rbx)
		chan->dcid = L2CAP_CID_CONN_LESS;
     440:	66 44 89 43 1a       	mov    %r8w,0x1a(%rbx)
     445:	49 8d b4 24 30 01 00 	lea    0x130(%r12),%rsi
     44c:	00 
		chan->omtu = L2CAP_DEFAULT_MTU;
     44d:	66 44 89 4b 20       	mov    %r9w,0x20(%rbx)
		break;
     452:	e9 2e ff ff ff       	jmpq   385 <__l2cap_chan_add+0xa5>
	return 0;
     457:	45 31 c0             	xor    %r8d,%r8d
     45a:	e9 f1 fe ff ff       	jmpq   350 <__l2cap_chan_add+0x70>
			chan->scid = L2CAP_CID_LE_DATA;
     45f:	b8 04 00 00 00       	mov    $0x4,%eax
			chan->omtu = L2CAP_LE_DEFAULT_MTU;
     464:	41 bb 17 00 00 00    	mov    $0x17,%r11d
     46a:	49 8d b4 24 30 01 00 	lea    0x130(%r12),%rsi
     471:	00 
			chan->scid = L2CAP_CID_LE_DATA;
     472:	66 89 43 1c          	mov    %ax,0x1c(%rbx)
			chan->dcid = L2CAP_CID_LE_DATA;
     476:	b8 04 00 00 00       	mov    $0x4,%eax
			chan->omtu = L2CAP_LE_DEFAULT_MTU;
     47b:	66 44 89 5b 20       	mov    %r11w,0x20(%rbx)
			chan->dcid = L2CAP_CID_LE_DATA;
     480:	66 89 43 1a          	mov    %ax,0x1a(%rbx)
     484:	e9 fc fe ff ff       	jmpq   385 <__l2cap_chan_add+0xa5>
	BT_DBG("conn %p, psm 0x%2.2x, dcid 0x%4.4x", conn,
     489:	0f b7 4e 18          	movzwl 0x18(%rsi),%ecx
     48d:	44 0f b7 46 1a       	movzwl 0x1a(%rsi),%r8d
     492:	48 89 fa             	mov    %rdi,%rdx
     495:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
     49c:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
     4a3:	31 c0                	xor    %eax,%eax
     4a5:	e8 00 00 00 00       	callq  4aa <__l2cap_chan_add+0x1ca>
     4aa:	e9 50 fe ff ff       	jmpq   2ff <__l2cap_chan_add+0x1f>
     4af:	90                   	nop

00000000000004b0 <l2cap_get_ident>:
{
     4b0:	55                   	push   %rbp
     4b1:	48 89 e5             	mov    %rsp,%rbp
     4b4:	53                   	push   %rbx
     4b5:	48 83 ec 08          	sub    $0x8,%rsp
     4b9:	e8 00 00 00 00       	callq  4be <l2cap_get_ident+0xe>
     4be:	48 89 fb             	mov    %rdi,%rbx
	raw_spin_lock_init(&(_lock)->rlock);		\
} while (0)

static inline void spin_lock(spinlock_t *lock)
{
	raw_spin_lock(&lock->rlock);
     4c1:	48 8d bf a0 00 00 00 	lea    0xa0(%rdi),%rdi
     4c8:	e8 00 00 00 00       	callq  4cd <l2cap_get_ident+0x1d>
	if (++conn->tx_ident > 128)
     4cd:	0f b6 83 b4 00 00 00 	movzbl 0xb4(%rbx),%eax
     4d4:	83 c0 01             	add    $0x1,%eax
     4d7:	3c 80                	cmp    $0x80,%al
     4d9:	76 1d                	jbe    4f8 <l2cap_get_ident+0x48>
		conn->tx_ident = 1;
     4db:	c6 83 b4 00 00 00 01 	movb   $0x1,0xb4(%rbx)
     4e2:	b8 01 00 00 00       	mov    $0x1,%eax
	return cmpxchg(&lock->head_tail, old.head_tail, new.head_tail) == old.head_tail;
}

static __always_inline void __ticket_spin_unlock(arch_spinlock_t *lock)
{
	__add(&lock->tickets.head, 1, UNLOCK_LOCK_PREFIX);
     4e7:	80 83 a0 00 00 00 01 	addb   $0x1,0xa0(%rbx)
}
     4ee:	48 83 c4 08          	add    $0x8,%rsp
     4f2:	5b                   	pop    %rbx
     4f3:	5d                   	pop    %rbp
     4f4:	c3                   	retq   
     4f5:	0f 1f 00             	nopl   (%rax)
	if (++conn->tx_ident > 128)
     4f8:	88 83 b4 00 00 00    	mov    %al,0xb4(%rbx)
     4fe:	eb e7                	jmp    4e7 <l2cap_get_ident+0x37>

0000000000000500 <l2cap_do_send>:
{
     500:	55                   	push   %rbp
     501:	48 89 e5             	mov    %rsp,%rbp
     504:	41 55                	push   %r13
     506:	41 54                	push   %r12
     508:	53                   	push   %rbx
     509:	48 83 ec 08          	sub    $0x8,%rsp
     50d:	e8 00 00 00 00       	callq  512 <l2cap_do_send+0x12>
	BT_DBG("chan %p, skb %p len %d priority %u", chan, skb, skb->len,
     512:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 519 <l2cap_do_send+0x19>
	struct hci_conn *hcon = chan->conn->hcon;
     519:	48 8b 47 08          	mov    0x8(%rdi),%rax
{
     51d:	48 89 fb             	mov    %rdi,%rbx
     520:	49 89 f4             	mov    %rsi,%r12
	struct hci_conn *hcon = chan->conn->hcon;
     523:	4c 8b 28             	mov    (%rax),%r13
	BT_DBG("chan %p, skb %p len %d priority %u", chan, skb, skb->len,
     526:	75 55                	jne    57d <l2cap_do_send+0x7d>
		(addr[nr / BITS_PER_LONG])) != 0;
     528:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
     52f:	ba 02 00 00 00       	mov    $0x2,%edx
	if (!test_bit(FLAG_FLUSHABLE, &chan->flags) &&
     534:	a8 08                	test   $0x8,%al
     536:	75 18                	jne    550 <l2cap_do_send+0x50>
					lmp_no_flush_capable(hcon->hdev))
     538:	49 8b 85 18 04 00 00 	mov    0x418(%r13),%rax
     53f:	0f b6 80 47 02 00 00 	movzbl 0x247(%rax),%eax
     546:	83 e0 40             	and    $0x40,%eax
	if (!test_bit(FLAG_FLUSHABLE, &chan->flags) &&
     549:	3c 01                	cmp    $0x1,%al
     54b:	19 d2                	sbb    %edx,%edx
     54d:	83 e2 02             	and    $0x2,%edx
     550:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	hci_send_acl(chan->conn->hchan, skb, flags);
     557:	4c 89 e6             	mov    %r12,%rsi
     55a:	48 d1 e8             	shr    %rax
     55d:	83 e0 01             	and    $0x1,%eax
	bt_cb(skb)->force_active = test_bit(FLAG_FORCE_ACTIVE, &chan->flags);
     560:	41 88 44 24 2c       	mov    %al,0x2c(%r12)
	hci_send_acl(chan->conn->hchan, skb, flags);
     565:	48 8b 43 08          	mov    0x8(%rbx),%rax
     569:	48 8b 78 08          	mov    0x8(%rax),%rdi
     56d:	e8 00 00 00 00       	callq  572 <l2cap_do_send+0x72>
}
     572:	48 83 c4 08          	add    $0x8,%rsp
     576:	5b                   	pop    %rbx
     577:	41 5c                	pop    %r12
     579:	41 5d                	pop    %r13
     57b:	5d                   	pop    %rbp
     57c:	c3                   	retq   
	BT_DBG("chan %p, skb %p len %d priority %u", chan, skb, skb->len,
     57d:	44 8b 4e 78          	mov    0x78(%rsi),%r9d
     581:	44 8b 46 68          	mov    0x68(%rsi),%r8d
     585:	48 89 f1             	mov    %rsi,%rcx
     588:	48 89 fa             	mov    %rdi,%rdx
     58b:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
     592:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
     599:	31 c0                	xor    %eax,%eax
     59b:	e8 00 00 00 00       	callq  5a0 <l2cap_do_send+0xa0>
     5a0:	eb 86                	jmp    528 <l2cap_do_send+0x28>
     5a2:	0f 1f 40 00          	nopl   0x0(%rax)
     5a6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
     5ad:	00 00 00 

00000000000005b0 <l2cap_add_conf_opt>:
{
     5b0:	55                   	push   %rbp
     5b1:	48 89 e5             	mov    %rsp,%rbp
     5b4:	41 57                	push   %r15
     5b6:	41 56                	push   %r14
     5b8:	41 55                	push   %r13
     5ba:	41 54                	push   %r12
     5bc:	53                   	push   %rbx
     5bd:	48 83 ec 18          	sub    $0x18,%rsp
     5c1:	e8 00 00 00 00       	callq  5c6 <l2cap_add_conf_opt+0x16>
	BT_DBG("type 0x%2.2x len %d val 0x%lx", type, len, val);
     5c6:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 5cd <l2cap_add_conf_opt+0x1d>
	struct l2cap_conf_opt *opt = *ptr;
     5cd:	4c 8b 2f             	mov    (%rdi),%r13
{
     5d0:	49 89 fc             	mov    %rdi,%r12
     5d3:	41 89 f1             	mov    %esi,%r9d
     5d6:	89 d3                	mov    %edx,%ebx
     5d8:	49 89 cf             	mov    %rcx,%r15
     5db:	41 89 d2             	mov    %edx,%r10d
	BT_DBG("type 0x%2.2x len %d val 0x%lx", type, len, val);
     5de:	75 67                	jne    647 <l2cap_add_conf_opt+0x97>
     5e0:	44 0f b6 f2          	movzbl %dl,%r14d
	switch (len) {
     5e4:	80 fb 02             	cmp    $0x2,%bl
	opt->type = type;
     5e7:	45 88 4d 00          	mov    %r9b,0x0(%r13)
	opt->len  = len;
     5eb:	41 88 5d 01          	mov    %bl,0x1(%r13)
	switch (len) {
     5ef:	74 4f                	je     640 <l2cap_add_conf_opt+0x90>
     5f1:	80 fb 04             	cmp    $0x4,%bl
     5f4:	74 3a                	je     630 <l2cap_add_conf_opt+0x80>
     5f6:	80 fb 01             	cmp    $0x1,%bl
     5f9:	74 2d                	je     628 <l2cap_add_conf_opt+0x78>
		memcpy(opt->val, (void *) val, len);
     5fb:	49 8d 7d 02          	lea    0x2(%r13),%rdi
     5ff:	41 0f b6 d2          	movzbl %r10b,%edx
     603:	4c 89 fe             	mov    %r15,%rsi
     606:	e8 00 00 00 00       	callq  60b <l2cap_add_conf_opt+0x5b>
	*ptr += L2CAP_CONF_OPT_SIZE + len;
     60b:	41 83 c6 02          	add    $0x2,%r14d
     60f:	4d 63 f6             	movslq %r14d,%r14
     612:	4d 01 34 24          	add    %r14,(%r12)
}
     616:	48 83 c4 18          	add    $0x18,%rsp
     61a:	5b                   	pop    %rbx
     61b:	41 5c                	pop    %r12
     61d:	41 5d                	pop    %r13
     61f:	41 5e                	pop    %r14
     621:	41 5f                	pop    %r15
     623:	5d                   	pop    %rbp
     624:	c3                   	retq   
     625:	0f 1f 00             	nopl   (%rax)
		*((u8 *) opt->val)  = val;
     628:	45 88 7d 02          	mov    %r15b,0x2(%r13)
		break;
     62c:	eb dd                	jmp    60b <l2cap_add_conf_opt+0x5b>
     62e:	66 90                	xchg   %ax,%ax
		put_unaligned_le32(val, opt->val);
     630:	45 89 7d 02          	mov    %r15d,0x2(%r13)
     634:	eb d5                	jmp    60b <l2cap_add_conf_opt+0x5b>
     636:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
     63d:	00 00 00 
		put_unaligned_le16(val, opt->val);
     640:	66 45 89 7d 02       	mov    %r15w,0x2(%r13)
     645:	eb c4                	jmp    60b <l2cap_add_conf_opt+0x5b>
	BT_DBG("type 0x%2.2x len %d val 0x%lx", type, len, val);
     647:	44 0f b6 f2          	movzbl %dl,%r14d
     64b:	89 75 cc             	mov    %esi,-0x34(%rbp)
     64e:	40 0f b6 d6          	movzbl %sil,%edx
     652:	49 89 c8             	mov    %rcx,%r8
     655:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
     65c:	44 89 f1             	mov    %r14d,%ecx
     65f:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
     666:	31 c0                	xor    %eax,%eax
     668:	44 89 55 c8          	mov    %r10d,-0x38(%rbp)
     66c:	e8 00 00 00 00       	callq  671 <l2cap_add_conf_opt+0xc1>
     671:	44 8b 55 c8          	mov    -0x38(%rbp),%r10d
     675:	44 8b 4d cc          	mov    -0x34(%rbp),%r9d
     679:	e9 66 ff ff ff       	jmpq   5e4 <l2cap_add_conf_opt+0x34>
     67e:	66 90                	xchg   %ax,%ax

0000000000000680 <l2cap_add_opt_efs>:
{
     680:	55                   	push   %rbp
     681:	48 89 e5             	mov    %rsp,%rbp
     684:	48 83 ec 10          	sub    $0x10,%rsp
     688:	e8 00 00 00 00       	callq  68d <l2cap_add_opt_efs+0xd>
	switch (chan->mode) {
     68d:	0f b6 46 24          	movzbl 0x24(%rsi),%eax
     691:	3c 03                	cmp    $0x3,%al
     693:	74 4b                	je     6e0 <l2cap_add_opt_efs+0x60>
     695:	3c 04                	cmp    $0x4,%al
     697:	75 3d                	jne    6d6 <l2cap_add_opt_efs+0x56>
		efs.msdu	= cpu_to_le16(chan->local_msdu);
     699:	0f b7 86 d0 00 00 00 	movzwl 0xd0(%rsi),%eax
		efs.id		= 1;
     6a0:	c6 45 f0 01          	movb   $0x1,-0x10(%rbp)
		efs.stype	= L2CAP_SERV_BESTEFFORT;
     6a4:	c6 45 f1 01          	movb   $0x1,-0xf(%rbp)
		efs.acc_lat	= 0;
     6a8:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
		efs.flush_to	= 0;
     6af:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
		efs.msdu	= cpu_to_le16(chan->local_msdu);
     6b6:	66 89 45 f2          	mov    %ax,-0xe(%rbp)
		efs.sdu_itime	= cpu_to_le32(chan->local_sdu_itime);
     6ba:	8b 86 d4 00 00 00    	mov    0xd4(%rsi),%eax
     6c0:	89 45 f4             	mov    %eax,-0xc(%rbp)
	l2cap_add_conf_opt(ptr, L2CAP_CONF_EFS, sizeof(efs),
     6c3:	48 8d 4d f0          	lea    -0x10(%rbp),%rcx
     6c7:	ba 10 00 00 00       	mov    $0x10,%edx
     6cc:	be 06 00 00 00       	mov    $0x6,%esi
     6d1:	e8 da fe ff ff       	callq  5b0 <l2cap_add_conf_opt>
}
     6d6:	c9                   	leaveq 
     6d7:	c3                   	retq   
     6d8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
     6df:	00 
		efs.id		= chan->local_id;
     6e0:	0f b6 86 ce 00 00 00 	movzbl 0xce(%rsi),%eax
		efs.acc_lat	= cpu_to_le32(L2CAP_DEFAULT_ACC_LAT);
     6e7:	c7 45 f8 ff ff ff ff 	movl   $0xffffffff,-0x8(%rbp)
		efs.flush_to	= cpu_to_le32(L2CAP_DEFAULT_FLUSH_TO);
     6ee:	c7 45 fc ff ff 00 00 	movl   $0xffff,-0x4(%rbp)
		efs.id		= chan->local_id;
     6f5:	88 45 f0             	mov    %al,-0x10(%rbp)
		efs.stype	= chan->local_stype;
     6f8:	0f b6 86 cf 00 00 00 	movzbl 0xcf(%rsi),%eax
     6ff:	88 45 f1             	mov    %al,-0xf(%rbp)
		efs.msdu	= cpu_to_le16(chan->local_msdu);
     702:	0f b7 86 d0 00 00 00 	movzwl 0xd0(%rsi),%eax
     709:	66 89 45 f2          	mov    %ax,-0xe(%rbp)
		efs.sdu_itime	= cpu_to_le32(chan->local_sdu_itime);
     70d:	8b 86 d4 00 00 00    	mov    0xd4(%rsi),%eax
     713:	89 45 f4             	mov    %eax,-0xc(%rbp)
		break;
     716:	eb ab                	jmp    6c3 <l2cap_add_opt_efs+0x43>
     718:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
     71f:	00 

0000000000000720 <l2cap_state_change>:
{
     720:	55                   	push   %rbp
     721:	48 89 e5             	mov    %rsp,%rbp
     724:	41 55                	push   %r13
     726:	41 54                	push   %r12
     728:	53                   	push   %rbx
     729:	48 83 ec 08          	sub    $0x8,%rsp
     72d:	e8 00 00 00 00       	callq  732 <l2cap_state_change+0x12>
	struct sock *sk = chan->sk;
     732:	48 8b 1f             	mov    (%rdi),%rbx
{
     735:	49 89 fc             	mov    %rdi,%r12
     738:	41 89 f5             	mov    %esi,%r13d

extern void lock_sock_nested(struct sock *sk, int subclass);

static inline void lock_sock(struct sock *sk)
{
	lock_sock_nested(sk, 0);
     73b:	31 f6                	xor    %esi,%esi
     73d:	48 89 df             	mov    %rbx,%rdi
     740:	e8 00 00 00 00       	callq  745 <l2cap_state_change+0x25>
	__l2cap_state_change(chan, state);
     745:	44 89 ee             	mov    %r13d,%esi
     748:	4c 89 e7             	mov    %r12,%rdi
     74b:	e8 40 f9 ff ff       	callq  90 <__l2cap_state_change>
	release_sock(sk);
     750:	48 89 df             	mov    %rbx,%rdi
     753:	e8 00 00 00 00       	callq  758 <l2cap_state_change+0x38>
}
     758:	48 83 c4 08          	add    $0x8,%rsp
     75c:	5b                   	pop    %rbx
     75d:	41 5c                	pop    %r12
     75f:	41 5d                	pop    %r13
     761:	5d                   	pop    %rbp
     762:	c3                   	retq   
     763:	0f 1f 00             	nopl   (%rax)
     766:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
     76d:	00 00 00 

0000000000000770 <l2cap_global_chan_by_scid>:
{
     770:	55                   	push   %rbp
     771:	48 89 e5             	mov    %rsp,%rbp
     774:	41 57                	push   %r15
     776:	41 56                	push   %r14
     778:	41 55                	push   %r13
     77a:	41 54                	push   %r12
     77c:	53                   	push   %rbx
     77d:	48 83 ec 38          	sub    $0x38,%rsp
     781:	e8 00 00 00 00       	callq  786 <l2cap_global_chan_by_scid+0x16>
     786:	41 89 fd             	mov    %edi,%r13d
	read_lock(&chan_list_lock);
     789:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
{
     790:	48 89 55 a8          	mov    %rdx,-0x58(%rbp)
     794:	48 89 4d a0          	mov    %rcx,-0x60(%rbp)
     798:	89 f3                	mov    %esi,%ebx
	read_lock(&chan_list_lock);
     79a:	e8 00 00 00 00       	callq  79f <l2cap_global_chan_by_scid+0x2f>
	list_for_each_entry(c, &chan_list, global_l) {
     79f:	48 8b 05 00 00 00 00 	mov    0x0(%rip),%rax        # 7a6 <l2cap_global_chan_by_scid+0x36>
	struct l2cap_chan *c, *c1 = NULL;
     7a6:	48 c7 45 b8 00 00 00 	movq   $0x0,-0x48(%rbp)
     7ad:	00 
	list_for_each_entry(c, &chan_list, global_l) {
     7ae:	48 3d 00 00 00 00    	cmp    $0x0,%rax
     7b4:	4c 8d b0 d8 fc ff ff 	lea    -0x328(%rax),%r14
     7bb:	75 2f                	jne    7ec <l2cap_global_chan_by_scid+0x7c>
     7bd:	e9 1e 01 00 00       	jmpq   8e0 <l2cap_global_chan_by_scid+0x170>
     7c2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		if (state && c->state != state)
     7c8:	41 0f b6 46 10       	movzbl 0x10(%r14),%eax
     7cd:	44 39 e8             	cmp    %r13d,%eax
     7d0:	74 22                	je     7f4 <l2cap_global_chan_by_scid+0x84>
	list_for_each_entry(c, &chan_list, global_l) {
     7d2:	49 8b 86 28 03 00 00 	mov    0x328(%r14),%rax
     7d9:	48 3d 00 00 00 00    	cmp    $0x0,%rax
     7df:	4c 8d b0 d8 fc ff ff 	lea    -0x328(%rax),%r14
     7e6:	0f 84 f4 00 00 00    	je     8e0 <l2cap_global_chan_by_scid+0x170>
		if (state && c->state != state)
     7ec:	45 85 ed             	test   %r13d,%r13d
		struct sock *sk = c->sk;
     7ef:	4d 8b 26             	mov    (%r14),%r12
		if (state && c->state != state)
     7f2:	75 d4                	jne    7c8 <l2cap_global_chan_by_scid+0x58>
		if (c->scid == cid) {
     7f4:	66 41 39 5e 1c       	cmp    %bx,0x1c(%r14)
     7f9:	75 d7                	jne    7d2 <l2cap_global_chan_by_scid+0x62>
			src_match = !bacmp(&bt_sk(sk)->src, src);
     7fb:	4d 8d bc 24 88 02 00 	lea    0x288(%r12),%r15
     802:	00 
	return memcmp(ba1, ba2, sizeof(bdaddr_t));
     803:	48 8b 75 a8          	mov    -0x58(%rbp),%rsi
     807:	ba 06 00 00 00       	mov    $0x6,%edx
     80c:	4c 89 ff             	mov    %r15,%rdi
     80f:	e8 00 00 00 00       	callq  814 <l2cap_global_chan_by_scid+0xa4>
     814:	48 8b 75 a0          	mov    -0x60(%rbp),%rsi
     818:	85 c0                	test   %eax,%eax
     81a:	ba 06 00 00 00       	mov    $0x6,%edx
     81f:	0f 94 45 b7          	sete   -0x49(%rbp)
			dst_match = !bacmp(&bt_sk(sk)->dst, dst);
     823:	49 81 c4 8e 02 00 00 	add    $0x28e,%r12
     82a:	4c 89 e7             	mov    %r12,%rdi
     82d:	e8 00 00 00 00       	callq  832 <l2cap_global_chan_by_scid+0xc2>
     832:	85 c0                	test   %eax,%eax
			if (src_match && dst_match) {
     834:	0f 94 45 b6          	sete   -0x4a(%rbp)
     838:	0f 84 bc 00 00 00    	je     8fa <l2cap_global_chan_by_scid+0x18a>
     83e:	48 8d 75 c4          	lea    -0x3c(%rbp),%rsi
     842:	4c 89 ff             	mov    %r15,%rdi
     845:	ba 06 00 00 00       	mov    $0x6,%edx
			src_any = !bacmp(&bt_sk(sk)->src, BDADDR_ANY);
     84a:	c6 45 c4 00          	movb   $0x0,-0x3c(%rbp)
     84e:	c6 45 c5 00          	movb   $0x0,-0x3b(%rbp)
     852:	c6 45 c6 00          	movb   $0x0,-0x3a(%rbp)
     856:	c6 45 c7 00          	movb   $0x0,-0x39(%rbp)
     85a:	c6 45 c8 00          	movb   $0x0,-0x38(%rbp)
     85e:	c6 45 c9 00          	movb   $0x0,-0x37(%rbp)
     862:	e8 00 00 00 00       	callq  867 <l2cap_global_chan_by_scid+0xf7>
     867:	48 8d 75 ca          	lea    -0x36(%rbp),%rsi
     86b:	ba 06 00 00 00       	mov    $0x6,%edx
     870:	4c 89 e7             	mov    %r12,%rdi
     873:	41 89 c7             	mov    %eax,%r15d
			dst_any = !bacmp(&bt_sk(sk)->dst, BDADDR_ANY);
     876:	c6 45 ca 00          	movb   $0x0,-0x36(%rbp)
     87a:	c6 45 cb 00          	movb   $0x0,-0x35(%rbp)
     87e:	c6 45 cc 00          	movb   $0x0,-0x34(%rbp)
     882:	c6 45 cd 00          	movb   $0x0,-0x33(%rbp)
     886:	c6 45 ce 00          	movb   $0x0,-0x32(%rbp)
     88a:	c6 45 cf 00          	movb   $0x0,-0x31(%rbp)
     88e:	e8 00 00 00 00       	callq  893 <l2cap_global_chan_by_scid+0x123>
     893:	85 c0                	test   %eax,%eax
			if ((src_match && dst_any) || (src_any && dst_match) ||
     895:	0f 94 c0             	sete   %al
     898:	75 06                	jne    8a0 <l2cap_global_chan_by_scid+0x130>
     89a:	80 7d b7 00          	cmpb   $0x0,-0x49(%rbp)
     89e:	75 0e                	jne    8ae <l2cap_global_chan_by_scid+0x13e>
			src_any = !bacmp(&bt_sk(sk)->src, BDADDR_ANY);
     8a0:	45 85 ff             	test   %r15d,%r15d
			if ((src_match && dst_any) || (src_any && dst_match) ||
     8a3:	0f 94 c2             	sete   %dl
     8a6:	75 18                	jne    8c0 <l2cap_global_chan_by_scid+0x150>
     8a8:	80 7d b6 00          	cmpb   $0x0,-0x4a(%rbp)
     8ac:	74 12                	je     8c0 <l2cap_global_chan_by_scid+0x150>
     8ae:	4c 89 75 b8          	mov    %r14,-0x48(%rbp)
     8b2:	e9 1b ff ff ff       	jmpq   7d2 <l2cap_global_chan_by_scid+0x62>
     8b7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
     8be:	00 00 
     8c0:	84 c0                	test   %al,%al
     8c2:	0f 84 0a ff ff ff    	je     7d2 <l2cap_global_chan_by_scid+0x62>
     8c8:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
     8cc:	84 d2                	test   %dl,%dl
     8ce:	49 0f 45 c6          	cmovne %r14,%rax
     8d2:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
     8d6:	e9 f7 fe ff ff       	jmpq   7d2 <l2cap_global_chan_by_scid+0x62>
     8db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
	return 0;
}

static inline void arch_read_unlock(arch_rwlock_t *rw)
{
	asm volatile(LOCK_PREFIX READ_LOCK_SIZE(inc) " %0"
     8e0:	f0 ff 05 00 00 00 00 	lock incl 0x0(%rip)        # 8e7 <l2cap_global_chan_by_scid+0x177>
}
     8e7:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
     8eb:	48 83 c4 38          	add    $0x38,%rsp
     8ef:	5b                   	pop    %rbx
     8f0:	41 5c                	pop    %r12
     8f2:	41 5d                	pop    %r13
     8f4:	41 5e                	pop    %r14
     8f6:	41 5f                	pop    %r15
     8f8:	5d                   	pop    %rbp
     8f9:	c3                   	retq   
			if (src_match && dst_match) {
     8fa:	80 7d b7 00          	cmpb   $0x0,-0x49(%rbp)
     8fe:	0f 84 3a ff ff ff    	je     83e <l2cap_global_chan_by_scid+0xce>
     904:	f0 ff 05 00 00 00 00 	lock incl 0x0(%rip)        # 90b <l2cap_global_chan_by_scid+0x19b>
				return c;
     90b:	4c 89 75 b8          	mov    %r14,-0x48(%rbp)
     90f:	eb d6                	jmp    8e7 <l2cap_global_chan_by_scid+0x177>
     911:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
     916:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
     91d:	00 00 00 

0000000000000920 <l2cap_global_chan_by_psm>:
{
     920:	55                   	push   %rbp
     921:	48 89 e5             	mov    %rsp,%rbp
     924:	41 57                	push   %r15
     926:	41 56                	push   %r14
     928:	41 55                	push   %r13
     92a:	41 54                	push   %r12
     92c:	53                   	push   %rbx
     92d:	48 83 ec 38          	sub    $0x38,%rsp
     931:	e8 00 00 00 00       	callq  936 <l2cap_global_chan_by_psm+0x16>
     936:	41 89 fd             	mov    %edi,%r13d
	read_lock(&chan_list_lock);
     939:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
{
     940:	48 89 55 a8          	mov    %rdx,-0x58(%rbp)
     944:	48 89 4d a0          	mov    %rcx,-0x60(%rbp)
     948:	89 f3                	mov    %esi,%ebx
	read_lock(&chan_list_lock);
     94a:	e8 00 00 00 00       	callq  94f <l2cap_global_chan_by_psm+0x2f>
	list_for_each_entry(c, &chan_list, global_l) {
     94f:	48 8b 05 00 00 00 00 	mov    0x0(%rip),%rax        # 956 <l2cap_global_chan_by_psm+0x36>
	struct l2cap_chan *c, *c1 = NULL;
     956:	48 c7 45 b8 00 00 00 	movq   $0x0,-0x48(%rbp)
     95d:	00 
	list_for_each_entry(c, &chan_list, global_l) {
     95e:	48 3d 00 00 00 00    	cmp    $0x0,%rax
     964:	4c 8d b0 d8 fc ff ff 	lea    -0x328(%rax),%r14
     96b:	75 2f                	jne    99c <l2cap_global_chan_by_psm+0x7c>
     96d:	e9 1e 01 00 00       	jmpq   a90 <l2cap_global_chan_by_psm+0x170>
     972:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		if (state && c->state != state)
     978:	41 0f b6 46 10       	movzbl 0x10(%r14),%eax
     97d:	44 39 e8             	cmp    %r13d,%eax
     980:	74 22                	je     9a4 <l2cap_global_chan_by_psm+0x84>
	list_for_each_entry(c, &chan_list, global_l) {
     982:	49 8b 86 28 03 00 00 	mov    0x328(%r14),%rax
     989:	48 3d 00 00 00 00    	cmp    $0x0,%rax
     98f:	4c 8d b0 d8 fc ff ff 	lea    -0x328(%rax),%r14
     996:	0f 84 f4 00 00 00    	je     a90 <l2cap_global_chan_by_psm+0x170>
		if (state && c->state != state)
     99c:	45 85 ed             	test   %r13d,%r13d
		struct sock *sk = c->sk;
     99f:	4d 8b 26             	mov    (%r14),%r12
		if (state && c->state != state)
     9a2:	75 d4                	jne    978 <l2cap_global_chan_by_psm+0x58>
		if (c->psm == psm) {
     9a4:	66 41 39 5e 18       	cmp    %bx,0x18(%r14)
     9a9:	75 d7                	jne    982 <l2cap_global_chan_by_psm+0x62>
			src_match = !bacmp(&bt_sk(sk)->src, src);
     9ab:	4d 8d bc 24 88 02 00 	lea    0x288(%r12),%r15
     9b2:	00 
     9b3:	48 8b 75 a8          	mov    -0x58(%rbp),%rsi
     9b7:	ba 06 00 00 00       	mov    $0x6,%edx
     9bc:	4c 89 ff             	mov    %r15,%rdi
     9bf:	e8 00 00 00 00       	callq  9c4 <l2cap_global_chan_by_psm+0xa4>
     9c4:	48 8b 75 a0          	mov    -0x60(%rbp),%rsi
     9c8:	85 c0                	test   %eax,%eax
     9ca:	ba 06 00 00 00       	mov    $0x6,%edx
     9cf:	0f 94 45 b7          	sete   -0x49(%rbp)
			dst_match = !bacmp(&bt_sk(sk)->dst, dst);
     9d3:	49 81 c4 8e 02 00 00 	add    $0x28e,%r12
     9da:	4c 89 e7             	mov    %r12,%rdi
     9dd:	e8 00 00 00 00       	callq  9e2 <l2cap_global_chan_by_psm+0xc2>
     9e2:	85 c0                	test   %eax,%eax
			if (src_match && dst_match) {
     9e4:	0f 94 45 b6          	sete   -0x4a(%rbp)
     9e8:	0f 84 bc 00 00 00    	je     aaa <l2cap_global_chan_by_psm+0x18a>
     9ee:	48 8d 75 c4          	lea    -0x3c(%rbp),%rsi
     9f2:	4c 89 ff             	mov    %r15,%rdi
     9f5:	ba 06 00 00 00       	mov    $0x6,%edx
			src_any = !bacmp(&bt_sk(sk)->src, BDADDR_ANY);
     9fa:	c6 45 c4 00          	movb   $0x0,-0x3c(%rbp)
     9fe:	c6 45 c5 00          	movb   $0x0,-0x3b(%rbp)
     a02:	c6 45 c6 00          	movb   $0x0,-0x3a(%rbp)
     a06:	c6 45 c7 00          	movb   $0x0,-0x39(%rbp)
     a0a:	c6 45 c8 00          	movb   $0x0,-0x38(%rbp)
     a0e:	c6 45 c9 00          	movb   $0x0,-0x37(%rbp)
     a12:	e8 00 00 00 00       	callq  a17 <l2cap_global_chan_by_psm+0xf7>
     a17:	48 8d 75 ca          	lea    -0x36(%rbp),%rsi
     a1b:	ba 06 00 00 00       	mov    $0x6,%edx
     a20:	4c 89 e7             	mov    %r12,%rdi
     a23:	41 89 c7             	mov    %eax,%r15d
			dst_any = !bacmp(&bt_sk(sk)->dst, BDADDR_ANY);
     a26:	c6 45 ca 00          	movb   $0x0,-0x36(%rbp)
     a2a:	c6 45 cb 00          	movb   $0x0,-0x35(%rbp)
     a2e:	c6 45 cc 00          	movb   $0x0,-0x34(%rbp)
     a32:	c6 45 cd 00          	movb   $0x0,-0x33(%rbp)
     a36:	c6 45 ce 00          	movb   $0x0,-0x32(%rbp)
     a3a:	c6 45 cf 00          	movb   $0x0,-0x31(%rbp)
     a3e:	e8 00 00 00 00       	callq  a43 <l2cap_global_chan_by_psm+0x123>
     a43:	85 c0                	test   %eax,%eax
			if ((src_match && dst_any) || (src_any && dst_match) ||
     a45:	0f 94 c0             	sete   %al
     a48:	75 06                	jne    a50 <l2cap_global_chan_by_psm+0x130>
     a4a:	80 7d b7 00          	cmpb   $0x0,-0x49(%rbp)
     a4e:	75 0e                	jne    a5e <l2cap_global_chan_by_psm+0x13e>
			src_any = !bacmp(&bt_sk(sk)->src, BDADDR_ANY);
     a50:	45 85 ff             	test   %r15d,%r15d
			if ((src_match && dst_any) || (src_any && dst_match) ||
     a53:	0f 94 c2             	sete   %dl
     a56:	75 18                	jne    a70 <l2cap_global_chan_by_psm+0x150>
     a58:	80 7d b6 00          	cmpb   $0x0,-0x4a(%rbp)
     a5c:	74 12                	je     a70 <l2cap_global_chan_by_psm+0x150>
     a5e:	4c 89 75 b8          	mov    %r14,-0x48(%rbp)
     a62:	e9 1b ff ff ff       	jmpq   982 <l2cap_global_chan_by_psm+0x62>
     a67:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
     a6e:	00 00 
     a70:	84 c0                	test   %al,%al
     a72:	0f 84 0a ff ff ff    	je     982 <l2cap_global_chan_by_psm+0x62>
     a78:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
     a7c:	84 d2                	test   %dl,%dl
     a7e:	49 0f 45 c6          	cmovne %r14,%rax
     a82:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
     a86:	e9 f7 fe ff ff       	jmpq   982 <l2cap_global_chan_by_psm+0x62>
     a8b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
     a90:	f0 ff 05 00 00 00 00 	lock incl 0x0(%rip)        # a97 <l2cap_global_chan_by_psm+0x177>
}
     a97:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
     a9b:	48 83 c4 38          	add    $0x38,%rsp
     a9f:	5b                   	pop    %rbx
     aa0:	41 5c                	pop    %r12
     aa2:	41 5d                	pop    %r13
     aa4:	41 5e                	pop    %r14
     aa6:	41 5f                	pop    %r15
     aa8:	5d                   	pop    %rbp
     aa9:	c3                   	retq   
			if (src_match && dst_match) {
     aaa:	80 7d b7 00          	cmpb   $0x0,-0x49(%rbp)
     aae:	0f 84 3a ff ff ff    	je     9ee <l2cap_global_chan_by_psm+0xce>
     ab4:	f0 ff 05 00 00 00 00 	lock incl 0x0(%rip)        # abb <l2cap_global_chan_by_psm+0x19b>
				return c;
     abb:	4c 89 75 b8          	mov    %r14,-0x48(%rbp)
     abf:	eb d6                	jmp    a97 <l2cap_global_chan_by_psm+0x177>
     ac1:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
     ac6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
     acd:	00 00 00 

0000000000000ad0 <l2cap_check_fcs>:

	kfree_skb(skb);
}

static int l2cap_check_fcs(struct l2cap_chan *chan,  struct sk_buff *skb)
{
     ad0:	55                   	push   %rbp
     ad1:	48 89 e5             	mov    %rsp,%rbp
     ad4:	41 55                	push   %r13
     ad6:	41 54                	push   %r12
     ad8:	53                   	push   %rbx
     ad9:	48 83 ec 08          	sub    $0x8,%rsp
     add:	e8 00 00 00 00       	callq  ae2 <l2cap_check_fcs+0x12>
     ae2:	48 8b 87 90 00 00 00 	mov    0x90(%rdi),%rax
     ae9:	49 89 f5             	mov    %rsi,%r13
     aec:	48 c1 e8 04          	shr    $0x4,%rax
     af0:	83 e0 01             	and    $0x1,%eax
	u16 our_fcs, rcv_fcs;
	int hdr_size;

	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
		hdr_size = L2CAP_EXT_HDR_SIZE;
     af3:	48 83 f8 01          	cmp    $0x1,%rax
     af7:	19 db                	sbb    %ebx,%ebx
		our_fcs = crc16(0, skb->data - hdr_size, skb->len + hdr_size);

		if (our_fcs != rcv_fcs)
			return -EBADMSG;
	}
	return 0;
     af9:	45 31 e4             	xor    %r12d,%r12d
		hdr_size = L2CAP_EXT_HDR_SIZE;
     afc:	83 e3 fe             	and    $0xfffffffe,%ebx
     aff:	83 c3 08             	add    $0x8,%ebx
	if (chan->fcs == L2CAP_FCS_CRC16) {
     b02:	80 7f 6f 01          	cmpb   $0x1,0x6f(%rdi)
     b06:	74 18                	je     b20 <l2cap_check_fcs+0x50>
}
     b08:	48 83 c4 08          	add    $0x8,%rsp
     b0c:	44 89 e0             	mov    %r12d,%eax
     b0f:	5b                   	pop    %rbx
     b10:	41 5c                	pop    %r12
     b12:	41 5d                	pop    %r13
     b14:	5d                   	pop    %rbp
     b15:	c3                   	retq   
     b16:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
     b1d:	00 00 00 
		skb_trim(skb, skb->len - L2CAP_FCS_SIZE);
     b20:	8b 46 68             	mov    0x68(%rsi),%eax
     b23:	4c 89 ef             	mov    %r13,%rdi
     b26:	8d 70 fe             	lea    -0x2(%rax),%esi
     b29:	e8 00 00 00 00       	callq  b2e <l2cap_check_fcs+0x5e>
		rcv_fcs = get_unaligned_le16(skb->data + skb->len);
     b2e:	41 8b 45 68          	mov    0x68(%r13),%eax
     b32:	49 8b b5 e0 00 00 00 	mov    0xe0(%r13),%rsi
		our_fcs = crc16(0, skb->data - hdr_size, skb->len + hdr_size);
     b39:	31 ff                	xor    %edi,%edi
		rcv_fcs = get_unaligned_le16(skb->data + skb->len);
     b3b:	89 c2                	mov    %eax,%edx
#define _LINUX_UNALIGNED_ACCESS_OK_H

#include <linux/kernel.h>
#include <asm/byteorder.h>

static inline u16 get_unaligned_le16(const void *p)
     b3d:	44 0f b7 2c 16       	movzwl (%rsi,%rdx,1),%r13d
		our_fcs = crc16(0, skb->data - hdr_size, skb->len + hdr_size);
     b42:	8d 14 03             	lea    (%rbx,%rax,1),%edx
     b45:	48 63 db             	movslq %ebx,%rbx
     b48:	48 29 de             	sub    %rbx,%rsi
     b4b:	e8 00 00 00 00       	callq  b50 <l2cap_check_fcs+0x80>
			return -EBADMSG;
     b50:	66 44 39 e8          	cmp    %r13w,%ax
     b54:	b8 b6 ff ff ff       	mov    $0xffffffb6,%eax
     b59:	44 0f 45 e0          	cmovne %eax,%r12d
}
     b5d:	48 83 c4 08          	add    $0x8,%rsp
     b61:	5b                   	pop    %rbx
     b62:	44 89 e0             	mov    %r12d,%eax
     b65:	41 5c                	pop    %r12
     b67:	41 5d                	pop    %r13
     b69:	5d                   	pop    %rbp
     b6a:	c3                   	retq   
     b6b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000000b70 <l2cap_debugfs_open>:

	return 0;
}

static int l2cap_debugfs_open(struct inode *inode, struct file *file)
{
     b70:	55                   	push   %rbp
     b71:	48 89 e5             	mov    %rsp,%rbp
     b74:	e8 00 00 00 00       	callq  b79 <l2cap_debugfs_open+0x9>
	return single_open(file, l2cap_debugfs_show, inode->i_private);
     b79:	48 8b 97 28 02 00 00 	mov    0x228(%rdi),%rdx
{
     b80:	48 89 f0             	mov    %rsi,%rax
	return single_open(file, l2cap_debugfs_show, inode->i_private);
     b83:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
     b8a:	48 89 c7             	mov    %rax,%rdi
     b8d:	e8 00 00 00 00       	callq  b92 <l2cap_debugfs_open+0x22>
}
     b92:	5d                   	pop    %rbp
     b93:	c3                   	retq   
     b94:	66 90                	xchg   %ax,%ax
     b96:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
     b9d:	00 00 00 

0000000000000ba0 <l2cap_debugfs_show>:
{
     ba0:	55                   	push   %rbp
     ba1:	48 89 e5             	mov    %rsp,%rbp
     ba4:	41 57                	push   %r15
     ba6:	41 56                	push   %r14
     ba8:	41 55                	push   %r13
     baa:	41 54                	push   %r12
     bac:	53                   	push   %rbx
     bad:	48 83 ec 68          	sub    $0x68,%rsp
     bb1:	e8 00 00 00 00       	callq  bb6 <l2cap_debugfs_show+0x16>
     bb6:	48 89 7d a8          	mov    %rdi,-0x58(%rbp)
	read_lock(&chan_list_lock);
     bba:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
     bc1:	e8 00 00 00 00       	callq  bc6 <l2cap_debugfs_show+0x26>
	list_for_each_entry(c, &chan_list, global_l) {
     bc6:	48 8b 05 00 00 00 00 	mov    0x0(%rip),%rax        # bcd <l2cap_debugfs_show+0x2d>
     bcd:	48 3d 00 00 00 00    	cmp    $0x0,%rax
     bd3:	48 8d 98 d8 fc ff ff 	lea    -0x328(%rax),%rbx
     bda:	0f 84 bd 00 00 00    	je     c9d <l2cap_debugfs_show+0xfd>
		struct sock *sk = c->sk;
     be0:	4c 8b 23             	mov    (%rbx),%r12
		seq_printf(f, "%s %s %d %d 0x%4.4x 0x%4.4x %d %d %d %d\n",
     be3:	44 0f b6 5b 2a       	movzbl 0x2a(%rbx),%r11d
     be8:	44 0f b7 53 20       	movzwl 0x20(%rbx),%r10d
     bed:	44 0f b7 4b 18       	movzwl 0x18(%rbx),%r9d
     bf2:	44 0f b6 43 10       	movzbl 0x10(%rbx),%r8d
     bf7:	0f b6 43 24          	movzbl 0x24(%rbx),%eax
     bfb:	49 8d bc 24 8e 02 00 	lea    0x28e(%r12),%rdi
     c02:	00 
     c03:	44 0f b7 7b 1e       	movzwl 0x1e(%rbx),%r15d
     c08:	44 0f b7 73 1a       	movzwl 0x1a(%rbx),%r14d
     c0d:	44 89 5d b4          	mov    %r11d,-0x4c(%rbp)
     c11:	44 0f b7 6b 1c       	movzwl 0x1c(%rbx),%r13d
     c16:	44 89 55 b8          	mov    %r10d,-0x48(%rbp)
     c1a:	44 89 4d bc          	mov    %r9d,-0x44(%rbp)
     c1e:	44 89 45 c8          	mov    %r8d,-0x38(%rbp)
     c22:	89 45 cc             	mov    %eax,-0x34(%rbp)
     c25:	e8 00 00 00 00       	callq  c2a <l2cap_debugfs_show+0x8a>
     c2a:	49 8d bc 24 88 02 00 	lea    0x288(%r12),%rdi
     c31:	00 
     c32:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
     c36:	e8 00 00 00 00       	callq  c3b <l2cap_debugfs_show+0x9b>
     c3b:	8b 55 cc             	mov    -0x34(%rbp),%edx
     c3e:	44 8b 5d b4          	mov    -0x4c(%rbp),%r11d
     c42:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
     c49:	44 8b 55 b8          	mov    -0x48(%rbp),%r10d
     c4d:	44 8b 4d bc          	mov    -0x44(%rbp),%r9d
     c51:	44 8b 45 c8          	mov    -0x38(%rbp),%r8d
     c55:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
     c59:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
     c5d:	89 54 24 28          	mov    %edx,0x28(%rsp)
     c61:	48 89 c2             	mov    %rax,%rdx
     c64:	44 89 5c 24 20       	mov    %r11d,0x20(%rsp)
     c69:	31 c0                	xor    %eax,%eax
     c6b:	44 89 54 24 18       	mov    %r10d,0x18(%rsp)
     c70:	44 89 7c 24 10       	mov    %r15d,0x10(%rsp)
     c75:	44 89 74 24 08       	mov    %r14d,0x8(%rsp)
     c7a:	44 89 2c 24          	mov    %r13d,(%rsp)
     c7e:	e8 00 00 00 00       	callq  c83 <l2cap_debugfs_show+0xe3>
	list_for_each_entry(c, &chan_list, global_l) {
     c83:	48 8b 83 28 03 00 00 	mov    0x328(%rbx),%rax
     c8a:	48 3d 00 00 00 00    	cmp    $0x0,%rax
     c90:	48 8d 98 d8 fc ff ff 	lea    -0x328(%rax),%rbx
     c97:	0f 85 43 ff ff ff    	jne    be0 <l2cap_debugfs_show+0x40>
     c9d:	f0 ff 05 00 00 00 00 	lock incl 0x0(%rip)        # ca4 <l2cap_debugfs_show+0x104>
}
     ca4:	48 83 c4 68          	add    $0x68,%rsp
     ca8:	31 c0                	xor    %eax,%eax
     caa:	5b                   	pop    %rbx
     cab:	41 5c                	pop    %r12
     cad:	41 5d                	pop    %r13
     caf:	41 5e                	pop    %r14
     cb1:	41 5f                	pop    %r15
     cb3:	5d                   	pop    %rbp
     cb4:	c3                   	retq   
     cb5:	90                   	nop
     cb6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
     cbd:	00 00 00 

0000000000000cc0 <l2cap_ertm_init>:
{
     cc0:	55                   	push   %rbp
	chan->sdu_len = 0;
     cc1:	31 c0                	xor    %eax,%eax
	chan->next_tx_seq = 0;
     cc3:	31 c9                	xor    %ecx,%ecx
	chan->expected_tx_seq = 0;
     cc5:	31 f6                	xor    %esi,%esi
	chan->unacked_frames = 0;
     cc7:	45 31 c0             	xor    %r8d,%r8d
	chan->buffer_seq = 0;
     cca:	45 31 c9             	xor    %r9d,%r9d
{
     ccd:	48 89 e5             	mov    %rsp,%rbp
     cd0:	53                   	push   %rbx
     cd1:	48 89 fb             	mov    %rdi,%rbx
	chan->frames_sent = 0;
     cd4:	45 31 d2             	xor    %r10d,%r10d
	chan->last_acked_seq = 0;
     cd7:	45 31 db             	xor    %r11d,%r11d
 * network layer or drivers should need annotation to consolidate the
 * main types of usage into 3 classes.
 */
static inline void skb_queue_head_init(struct sk_buff_head *list)
{
	spin_lock_init(&list->lock);
     cda:	31 d2                	xor    %edx,%edx
{
     cdc:	48 83 ec 08          	sub    $0x8,%rsp
	chan->next_tx_seq = 0;
     ce0:	66 89 8f 98 00 00 00 	mov    %cx,0x98(%rdi)
	chan->expected_tx_seq = 0;
     ce7:	66 89 b7 9c 00 00 00 	mov    %si,0x9c(%rdi)
	chan->sdu_len = 0;
     cee:	66 89 83 b0 00 00 00 	mov    %ax,0xb0(%rbx)
	skb_queue_head_init(&chan->tx_q);
     cf5:	48 8d 83 b8 02 00 00 	lea    0x2b8(%rbx),%rax
	chan->expected_ack_seq = 0;
     cfc:	31 ff                	xor    %edi,%edi
     cfe:	66 89 bb 9a 00 00 00 	mov    %di,0x9a(%rbx)
	chan->unacked_frames = 0;
     d05:	66 44 89 83 a8 00 00 	mov    %r8w,0xa8(%rbx)
     d0c:	00 
	list->prev = list->next = (struct sk_buff *)list;
     d0d:	48 89 83 b8 02 00 00 	mov    %rax,0x2b8(%rbx)
     d14:	48 89 83 c0 02 00 00 	mov    %rax,0x2c0(%rbx)
		return 0;
     d1b:	31 c0                	xor    %eax,%eax
	if (chan->mode != L2CAP_MODE_ERTM)
     d1d:	80 7b 24 03          	cmpb   $0x3,0x24(%rbx)
	chan->buffer_seq = 0;
     d21:	66 44 89 8b 9e 00 00 	mov    %r9w,0x9e(%rbx)
     d28:	00 
	chan->num_acked = 0;
     d29:	c6 83 ae 00 00 00 00 	movb   $0x0,0xae(%rbx)
	chan->frames_sent = 0;
     d30:	66 44 89 93 a6 00 00 	mov    %r10w,0xa6(%rbx)
     d37:	00 
	chan->last_acked_seq = 0;
     d38:	66 44 89 9b a4 00 00 	mov    %r11w,0xa4(%rbx)
     d3f:	00 
	chan->sdu = NULL;
     d40:	48 c7 83 b8 00 00 00 	movq   $0x0,0xb8(%rbx)
     d47:	00 00 00 00 
	chan->sdu_last_frag = NULL;
     d4b:	48 c7 83 c0 00 00 00 	movq   $0x0,0xc0(%rbx)
     d52:	00 00 00 00 
	spin_lock_init(&list->lock);
     d56:	66 89 93 cc 02 00 00 	mov    %dx,0x2cc(%rbx)
	list->qlen = 0;
     d5d:	c7 83 c8 02 00 00 00 	movl   $0x0,0x2c8(%rbx)
     d64:	00 00 00 
	if (chan->mode != L2CAP_MODE_ERTM)
     d67:	74 07                	je     d70 <l2cap_ertm_init+0xb0>
}
     d69:	48 83 c4 08          	add    $0x8,%rsp
     d6d:	5b                   	pop    %rbx
     d6e:	5d                   	pop    %rbp
     d6f:	c3                   	retq   
	INIT_DELAYED_WORK(&chan->retrans_timer, l2cap_retrans_timeout);
     d70:	48 8d 83 68 01 00 00 	lea    0x168(%rbx),%rax
     d77:	48 8d bb 80 01 00 00 	lea    0x180(%rbx),%rdi
     d7e:	31 d2                	xor    %edx,%edx
     d80:	31 f6                	xor    %esi,%esi
	chan->rx_state = L2CAP_RX_STATE_RECV;
     d82:	c6 43 7d 00          	movb   $0x0,0x7d(%rbx)
	chan->tx_state = L2CAP_TX_STATE_XMIT;
     d86:	c6 43 7c 00          	movb   $0x0,0x7c(%rbx)
	list->next = list;
     d8a:	48 89 83 68 01 00 00 	mov    %rax,0x168(%rbx)
	list->prev = list;
     d91:	48 89 83 70 01 00 00 	mov    %rax,0x170(%rbx)
	INIT_DELAYED_WORK(&chan->retrans_timer, l2cap_retrans_timeout);
     d98:	48 c7 83 60 01 00 00 	movq   $0x900,0x160(%rbx)
     d9f:	00 09 00 00 
     da3:	48 c7 83 78 01 00 00 	movq   $0x0,0x178(%rbx)
     daa:	00 00 00 00 
     dae:	e8 00 00 00 00       	callq  db3 <l2cap_ertm_init+0xf3>
	INIT_DELAYED_WORK(&chan->monitor_timer, l2cap_monitor_timeout);
     db3:	48 8d 83 d8 01 00 00 	lea    0x1d8(%rbx),%rax
     dba:	48 8d bb f0 01 00 00 	lea    0x1f0(%rbx),%rdi
     dc1:	31 d2                	xor    %edx,%edx
     dc3:	31 f6                	xor    %esi,%esi
     dc5:	48 c7 83 d0 01 00 00 	movq   $0x900,0x1d0(%rbx)
     dcc:	00 09 00 00 
     dd0:	48 c7 83 e8 01 00 00 	movq   $0x0,0x1e8(%rbx)
     dd7:	00 00 00 00 
	list->next = list;
     ddb:	48 89 83 d8 01 00 00 	mov    %rax,0x1d8(%rbx)
	list->prev = list;
     de2:	48 89 83 e0 01 00 00 	mov    %rax,0x1e0(%rbx)
     de9:	e8 00 00 00 00       	callq  dee <l2cap_ertm_init+0x12e>
	INIT_DELAYED_WORK(&chan->ack_timer, l2cap_ack_timeout);
     dee:	48 8d 83 48 02 00 00 	lea    0x248(%rbx),%rax
     df5:	48 8d bb 60 02 00 00 	lea    0x260(%rbx),%rdi
     dfc:	31 d2                	xor    %edx,%edx
     dfe:	31 f6                	xor    %esi,%esi
     e00:	48 c7 83 40 02 00 00 	movq   $0x900,0x240(%rbx)
     e07:	00 09 00 00 
     e0b:	48 c7 83 58 02 00 00 	movq   $0x0,0x258(%rbx)
     e12:	00 00 00 00 
	list->next = list;
     e16:	48 89 83 48 02 00 00 	mov    %rax,0x248(%rbx)
	list->prev = list;
     e1d:	48 89 83 50 02 00 00 	mov    %rax,0x250(%rbx)
     e24:	e8 00 00 00 00       	callq  e29 <l2cap_ertm_init+0x169>
	skb_queue_head_init(&chan->srej_q);
     e29:	48 8d 83 d0 02 00 00 	lea    0x2d0(%rbx),%rax
	err = l2cap_seq_list_init(&chan->srej_list, chan->tx_win);
     e30:	0f b7 73 70          	movzwl 0x70(%rbx),%esi
	spin_lock_init(&list->lock);
     e34:	31 d2                	xor    %edx,%edx
     e36:	48 8d bb e8 02 00 00 	lea    0x2e8(%rbx),%rdi
     e3d:	66 89 93 e4 02 00 00 	mov    %dx,0x2e4(%rbx)
	list->qlen = 0;
     e44:	c7 83 e0 02 00 00 00 	movl   $0x0,0x2e0(%rbx)
     e4b:	00 00 00 
	list->prev = list->next = (struct sk_buff *)list;
     e4e:	48 89 83 d0 02 00 00 	mov    %rax,0x2d0(%rbx)
     e55:	48 89 83 d8 02 00 00 	mov    %rax,0x2d8(%rbx)
	INIT_LIST_HEAD(&chan->srej_l);
     e5c:	48 8d 83 08 03 00 00 	lea    0x308(%rbx),%rax
	list->next = list;
     e63:	48 89 83 08 03 00 00 	mov    %rax,0x308(%rbx)
	list->prev = list;
     e6a:	48 89 83 10 03 00 00 	mov    %rax,0x310(%rbx)
	err = l2cap_seq_list_init(&chan->srej_list, chan->tx_win);
     e71:	e8 ca f3 ff ff       	callq  240 <l2cap_seq_list_init>
	if (err < 0)
     e76:	85 c0                	test   %eax,%eax
     e78:	0f 88 eb fe ff ff    	js     d69 <l2cap_ertm_init+0xa9>
	return l2cap_seq_list_init(&chan->retrans_list, chan->remote_tx_win);
     e7e:	0f b7 b3 c8 00 00 00 	movzwl 0xc8(%rbx),%esi
     e85:	48 8d bb f8 02 00 00 	lea    0x2f8(%rbx),%rdi
     e8c:	e8 af f3 ff ff       	callq  240 <l2cap_seq_list_init>
}
     e91:	48 83 c4 08          	add    $0x8,%rsp
     e95:	5b                   	pop    %rbx
     e96:	5d                   	pop    %rbp
     e97:	c3                   	retq   
     e98:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
     e9f:	00 

0000000000000ea0 <l2cap_conn_unreliable.constprop.37>:
static void l2cap_conn_unreliable(struct l2cap_conn *conn, int err)
     ea0:	55                   	push   %rbp
     ea1:	48 89 e5             	mov    %rsp,%rbp
     ea4:	41 54                	push   %r12
     ea6:	53                   	push   %rbx
     ea7:	e8 00 00 00 00       	callq  eac <l2cap_conn_unreliable.constprop.37+0xc>
	BT_DBG("conn %p", conn);
     eac:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # eb3 <l2cap_conn_unreliable.constprop.37+0x13>
static void l2cap_conn_unreliable(struct l2cap_conn *conn, int err)
     eb3:	48 89 fb             	mov    %rdi,%rbx
	BT_DBG("conn %p", conn);
     eb6:	75 69                	jne    f21 <l2cap_conn_unreliable.constprop.37+0x81>
	mutex_lock(&conn->chan_lock);
     eb8:	4c 8d a3 40 01 00 00 	lea    0x140(%rbx),%r12
     ebf:	4c 89 e7             	mov    %r12,%rdi
     ec2:	e8 00 00 00 00       	callq  ec7 <l2cap_conn_unreliable.constprop.37+0x27>
	list_for_each_entry(chan, &conn->chan_l, list) {
     ec7:	48 8b 93 30 01 00 00 	mov    0x130(%rbx),%rdx
     ece:	48 8d 8b 30 01 00 00 	lea    0x130(%rbx),%rcx
     ed5:	48 39 d1             	cmp    %rdx,%rcx
     ed8:	48 8d 82 e8 fc ff ff 	lea    -0x318(%rdx),%rax
     edf:	74 33                	je     f14 <l2cap_conn_unreliable.constprop.37+0x74>
     ee1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
     ee8:	48 8b 90 90 00 00 00 	mov    0x90(%rax),%rdx
		if (test_bit(FLAG_FORCE_RELIABLE, &chan->flags))
     eef:	83 e2 04             	and    $0x4,%edx
     ef2:	74 0d                	je     f01 <l2cap_conn_unreliable.constprop.37+0x61>
	struct l2cap_chan *chan;
     ef4:	48 8b 10             	mov    (%rax),%rdx
	sk->sk_err = err;
     ef7:	c7 82 7c 01 00 00 46 	movl   $0x46,0x17c(%rdx)
     efe:	00 00 00 
	list_for_each_entry(chan, &conn->chan_l, list) {
     f01:	48 8b 90 18 03 00 00 	mov    0x318(%rax),%rdx
     f08:	48 39 d1             	cmp    %rdx,%rcx
     f0b:	48 8d 82 e8 fc ff ff 	lea    -0x318(%rdx),%rax
     f12:	75 d4                	jne    ee8 <l2cap_conn_unreliable.constprop.37+0x48>
	mutex_unlock(&conn->chan_lock);
     f14:	4c 89 e7             	mov    %r12,%rdi
     f17:	e8 00 00 00 00       	callq  f1c <l2cap_conn_unreliable.constprop.37+0x7c>
}
     f1c:	5b                   	pop    %rbx
     f1d:	41 5c                	pop    %r12
     f1f:	5d                   	pop    %rbp
     f20:	c3                   	retq   
	BT_DBG("conn %p", conn);
     f21:	48 89 fa             	mov    %rdi,%rdx
     f24:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
     f2b:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
     f32:	31 c0                	xor    %eax,%eax
     f34:	e8 00 00 00 00       	callq  f39 <l2cap_conn_unreliable.constprop.37+0x99>
     f39:	e9 7a ff ff ff       	jmpq   eb8 <l2cap_conn_unreliable.constprop.37+0x18>
     f3e:	66 90                	xchg   %ax,%ax

0000000000000f40 <l2cap_conn_add.part.29>:
static struct l2cap_conn *l2cap_conn_add(struct hci_conn *hcon, u8 status)
     f40:	55                   	push   %rbp
     f41:	48 89 e5             	mov    %rsp,%rbp
     f44:	41 55                	push   %r13
     f46:	41 54                	push   %r12
     f48:	53                   	push   %rbx
     f49:	48 83 ec 08          	sub    $0x8,%rsp
     f4d:	e8 00 00 00 00       	callq  f52 <l2cap_conn_add.part.29+0x12>
     f52:	49 89 fc             	mov    %rdi,%r12
	hchan = hci_chan_create(hcon);
     f55:	e8 00 00 00 00       	callq  f5a <l2cap_conn_add.part.29+0x1a>
	if (!hchan)
     f5a:	48 85 c0             	test   %rax,%rax
	hchan = hci_chan_create(hcon);
     f5d:	49 89 c5             	mov    %rax,%r13
	if (!hchan)
     f60:	0f 84 8a 01 00 00    	je     10f0 <l2cap_conn_add.part.29+0x1b0>
	return kmalloc_caches[index];
     f66:	48 8b 3d 00 00 00 00 	mov    0x0(%rip),%rdi        # f6d <l2cap_conn_add.part.29+0x2d>
			if (!s)
     f6d:	48 85 ff             	test   %rdi,%rdi
     f70:	0f 84 12 01 00 00    	je     1088 <l2cap_conn_add.part.29+0x148>
			return kmem_cache_alloc_trace(s, flags, size);
     f76:	ba 60 01 00 00       	mov    $0x160,%edx
     f7b:	be 20 80 00 00       	mov    $0x8020,%esi
     f80:	e8 00 00 00 00       	callq  f85 <l2cap_conn_add.part.29+0x45>
	if (!conn) {
     f85:	48 85 c0             	test   %rax,%rax
     f88:	48 89 c3             	mov    %rax,%rbx
     f8b:	0f 84 47 01 00 00    	je     10d8 <l2cap_conn_add.part.29+0x198>
	hcon->l2cap_data = conn;
     f91:	49 89 9c 24 20 04 00 	mov    %rbx,0x420(%r12)
     f98:	00 
	conn->hcon = hcon;
     f99:	4c 89 23             	mov    %r12,(%rbx)
	conn->hchan = hchan;
     f9c:	4c 89 6b 08          	mov    %r13,0x8(%rbx)
	BT_DBG("hcon %p conn %p hchan %p", hcon, conn, hchan);
     fa0:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # fa7 <l2cap_conn_add.part.29+0x67>
     fa7:	0f 85 4a 01 00 00    	jne    10f7 <l2cap_conn_add.part.29+0x1b7>
	if (hcon->hdev->le_mtu && hcon->type == LE_LINK)
     fad:	49 8b 84 24 18 04 00 	mov    0x418(%r12),%rax
     fb4:	00 
     fb5:	8b 90 08 03 00 00    	mov    0x308(%rax),%edx
     fbb:	85 d2                	test   %edx,%edx
     fbd:	0f 85 ad 00 00 00    	jne    1070 <l2cap_conn_add.part.29+0x130>
		conn->mtu = hcon->hdev->acl_mtu;
     fc3:	8b 80 00 03 00 00    	mov    0x300(%rax),%eax
     fc9:	89 43 20             	mov    %eax,0x20(%rbx)
	conn->src = &hcon->hdev->bdaddr;
     fcc:	49 8b 84 24 18 04 00 	mov    0x418(%r12),%rax
     fd3:	00 
	mutex_init(&conn->chan_lock);
     fd4:	48 8d bb 40 01 00 00 	lea    0x140(%rbx),%rdi
	conn->feat_mask = 0;
     fdb:	c7 43 24 00 00 00 00 	movl   $0x0,0x24(%rbx)
	mutex_init(&conn->chan_lock);
     fe2:	48 c7 c2 00 00 00 00 	mov    $0x0,%rdx
     fe9:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
	conn->src = &hcon->hdev->bdaddr;
     ff0:	48 83 c0 44          	add    $0x44,%rax
     ff4:	48 89 43 18          	mov    %rax,0x18(%rbx)
	conn->dst = &hcon->dst;
     ff8:	49 8d 44 24 14       	lea    0x14(%r12),%rax
     ffd:	48 89 43 10          	mov    %rax,0x10(%rbx)
	spin_lock_init(&conn->lock);
    1001:	31 c0                	xor    %eax,%eax
    1003:	66 89 83 a0 00 00 00 	mov    %ax,0xa0(%rbx)
	mutex_init(&conn->chan_lock);
    100a:	e8 00 00 00 00       	callq  100f <l2cap_conn_add.part.29+0xcf>
	INIT_LIST_HEAD(&conn->chan_l);
    100f:	48 8d 83 30 01 00 00 	lea    0x130(%rbx),%rax
	list->next = list;
    1016:	48 89 83 30 01 00 00 	mov    %rax,0x130(%rbx)
	list->prev = list;
    101d:	48 89 83 38 01 00 00 	mov    %rax,0x138(%rbx)
	if (hcon->type == LE_LINK)
    1024:	41 80 7c 24 21 80    	cmpb   $0x80,0x21(%r12)
    102a:	74 6c                	je     1098 <l2cap_conn_add.part.29+0x158>
		INIT_DELAYED_WORK(&conn->info_timer, l2cap_info_timeout);
    102c:	48 8d 43 38          	lea    0x38(%rbx),%rax
    1030:	48 8d 7b 50          	lea    0x50(%rbx),%rdi
    1034:	48 c7 43 30 00 09 00 	movq   $0x900,0x30(%rbx)
    103b:	00 
    103c:	48 c7 43 48 00 00 00 	movq   $0x0,0x48(%rbx)
    1043:	00 
    1044:	31 d2                	xor    %edx,%edx
    1046:	31 f6                	xor    %esi,%esi
	list->next = list;
    1048:	48 89 43 38          	mov    %rax,0x38(%rbx)
	list->prev = list;
    104c:	48 89 43 40          	mov    %rax,0x40(%rbx)
    1050:	e8 00 00 00 00       	callq  1055 <l2cap_conn_add.part.29+0x115>
	conn->disc_reason = HCI_ERROR_REMOTE_USER_TERM;
    1055:	c6 83 b5 00 00 00 13 	movb   $0x13,0xb5(%rbx)
    105c:	48 89 d8             	mov    %rbx,%rax
}
    105f:	48 83 c4 08          	add    $0x8,%rsp
    1063:	5b                   	pop    %rbx
    1064:	41 5c                	pop    %r12
    1066:	41 5d                	pop    %r13
    1068:	5d                   	pop    %rbp
    1069:	c3                   	retq   
    106a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
	if (hcon->hdev->le_mtu && hcon->type == LE_LINK)
    1070:	41 80 7c 24 21 80    	cmpb   $0x80,0x21(%r12)
    1076:	0f 85 47 ff ff ff    	jne    fc3 <l2cap_conn_add.part.29+0x83>
		conn->mtu = hcon->hdev->le_mtu;
    107c:	89 53 20             	mov    %edx,0x20(%rbx)
    107f:	e9 48 ff ff ff       	jmpq   fcc <l2cap_conn_add.part.29+0x8c>
    1084:	0f 1f 40 00          	nopl   0x0(%rax)
				return ZERO_SIZE_PTR;
    1088:	bb 10 00 00 00       	mov    $0x10,%ebx
    108d:	e9 ff fe ff ff       	jmpq   f91 <l2cap_conn_add.part.29+0x51>
    1092:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		INIT_DELAYED_WORK(&conn->security_timer, security_timeout);
    1098:	48 8d 83 c0 00 00 00 	lea    0xc0(%rbx),%rax
    109f:	48 8d bb d8 00 00 00 	lea    0xd8(%rbx),%rdi
    10a6:	48 c7 83 b8 00 00 00 	movq   $0x900,0xb8(%rbx)
    10ad:	00 09 00 00 
    10b1:	48 c7 83 d0 00 00 00 	movq   $0x0,0xd0(%rbx)
    10b8:	00 00 00 00 
    10bc:	31 d2                	xor    %edx,%edx
    10be:	31 f6                	xor    %esi,%esi
	list->next = list;
    10c0:	48 89 83 c0 00 00 00 	mov    %rax,0xc0(%rbx)
	list->prev = list;
    10c7:	48 89 83 c8 00 00 00 	mov    %rax,0xc8(%rbx)
    10ce:	e8 00 00 00 00       	callq  10d3 <l2cap_conn_add.part.29+0x193>
    10d3:	e9 7d ff ff ff       	jmpq   1055 <l2cap_conn_add.part.29+0x115>
		hci_chan_del(hchan);
    10d8:	4c 89 ef             	mov    %r13,%rdi
    10db:	e8 00 00 00 00       	callq  10e0 <l2cap_conn_add.part.29+0x1a0>
		return NULL;
    10e0:	31 c0                	xor    %eax,%eax
    10e2:	e9 78 ff ff ff       	jmpq   105f <l2cap_conn_add.part.29+0x11f>
    10e7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    10ee:	00 00 
		return NULL;
    10f0:	31 c0                	xor    %eax,%eax
    10f2:	e9 68 ff ff ff       	jmpq   105f <l2cap_conn_add.part.29+0x11f>
	BT_DBG("hcon %p conn %p hchan %p", hcon, conn, hchan);
    10f7:	4d 89 e8             	mov    %r13,%r8
    10fa:	48 89 d9             	mov    %rbx,%rcx
    10fd:	4c 89 e2             	mov    %r12,%rdx
    1100:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    1107:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    110e:	31 c0                	xor    %eax,%eax
    1110:	e8 00 00 00 00       	callq  1115 <l2cap_conn_add.part.29+0x1d5>
    1115:	e9 93 fe ff ff       	jmpq   fad <l2cap_conn_add.part.29+0x6d>
    111a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000001120 <l2cap_reassemble_sdu>:
{
    1120:	55                   	push   %rbp
    1121:	48 89 e5             	mov    %rsp,%rbp
    1124:	41 54                	push   %r12
    1126:	53                   	push   %rbx
    1127:	48 83 ec 10          	sub    $0x10,%rsp
    112b:	e8 00 00 00 00       	callq  1130 <l2cap_reassemble_sdu+0x10>
    1130:	48 8b 87 90 00 00 00 	mov    0x90(%rdi),%rax
    1137:	48 89 fb             	mov    %rdi,%rbx
    113a:	49 89 f4             	mov    %rsi,%r12
		return L2CAP_CTRL_FRAME_TYPE;
}

static inline __u8 __get_ctrl_sar(struct l2cap_chan *chan, __u32 ctrl)
{
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    113d:	a8 10                	test   $0x10,%al
    113f:	74 57                	je     1198 <l2cap_reassemble_sdu+0x78>
		return (ctrl & L2CAP_EXT_CTRL_SAR) >> L2CAP_EXT_CTRL_SAR_SHIFT;
    1141:	81 e2 00 00 03 00    	and    $0x30000,%edx
    1147:	c1 ea 10             	shr    $0x10,%edx
	switch (__get_ctrl_sar(chan, control)) {
    114a:	80 fa 02             	cmp    $0x2,%dl
    114d:	74 57                	je     11a6 <l2cap_reassemble_sdu+0x86>
    114f:	80 fa 03             	cmp    $0x3,%dl
    1152:	0f 84 60 01 00 00    	je     12b8 <l2cap_reassemble_sdu+0x198>
    1158:	80 fa 01             	cmp    $0x1,%dl
    115b:	0f 84 ff 00 00 00    	je     1260 <l2cap_reassemble_sdu+0x140>
		if (chan->sdu)
    1161:	48 83 bb b8 00 00 00 	cmpq   $0x0,0xb8(%rbx)
    1168:	00 
    1169:	0f 85 59 01 00 00    	jne    12c8 <l2cap_reassemble_sdu+0x1a8>
		err = chan->ops->recv(chan->data, skb);
    116f:	48 8b 83 40 03 00 00 	mov    0x340(%rbx),%rax
    1176:	48 8b bb 38 03 00 00 	mov    0x338(%rbx),%rdi
    117d:	4c 89 e6             	mov    %r12,%rsi
    1180:	ff 50 10             	callq  *0x10(%rax)
	if (err) {
    1183:	85 c0                	test   %eax,%eax
    1185:	0f 85 42 01 00 00    	jne    12cd <l2cap_reassemble_sdu+0x1ad>
}
    118b:	48 83 c4 10          	add    $0x10,%rsp
    118f:	5b                   	pop    %rbx
    1190:	41 5c                	pop    %r12
    1192:	5d                   	pop    %rbp
    1193:	c3                   	retq   
    1194:	0f 1f 40 00          	nopl   0x0(%rax)
	else
		return (ctrl & L2CAP_CTRL_SAR) >> L2CAP_CTRL_SAR_SHIFT;
    1198:	81 e2 00 c0 00 00    	and    $0xc000,%edx
    119e:	c1 ea 0e             	shr    $0xe,%edx
	switch (__get_ctrl_sar(chan, control)) {
    11a1:	80 fa 02             	cmp    $0x2,%dl
    11a4:	75 a9                	jne    114f <l2cap_reassemble_sdu+0x2f>
		if (!chan->sdu)
    11a6:	48 8b 83 b8 00 00 00 	mov    0xb8(%rbx),%rax
    11ad:	48 85 c0             	test   %rax,%rax
    11b0:	0f 84 12 01 00 00    	je     12c8 <l2cap_reassemble_sdu+0x1a8>
	return skb->head + skb->end;
    11b6:	8b 90 d0 00 00 00    	mov    0xd0(%rax),%edx
    11bc:	48 03 90 d8 00 00 00 	add    0xd8(%rax),%rdx
	if (!skb_has_frag_list(skb))
    11c3:	48 83 7a 08 00       	cmpq   $0x0,0x8(%rdx)
    11c8:	0f 84 c2 01 00 00    	je     1390 <l2cap_reassemble_sdu+0x270>
	new_frag->next = NULL;
    11ce:	49 c7 04 24 00 00 00 	movq   $0x0,(%r12)
    11d5:	00 
	(*last_frag)->next = new_frag;
    11d6:	48 8b 93 c0 00 00 00 	mov    0xc0(%rbx),%rdx
    11dd:	4c 89 22             	mov    %r12,(%rdx)
	*last_frag = new_frag;
    11e0:	4c 89 a3 c0 00 00 00 	mov    %r12,0xc0(%rbx)
	skb->len += new_frag->len;
    11e7:	41 8b 54 24 68       	mov    0x68(%r12),%edx
    11ec:	01 50 68             	add    %edx,0x68(%rax)
	skb->data_len += new_frag->len;
    11ef:	41 8b 54 24 68       	mov    0x68(%r12),%edx
    11f4:	01 50 6c             	add    %edx,0x6c(%rax)
	skb->truesize += new_frag->truesize;
    11f7:	41 8b 94 24 e8 00 00 	mov    0xe8(%r12),%edx
    11fe:	00 
    11ff:	01 90 e8 00 00 00    	add    %edx,0xe8(%rax)
		if (chan->sdu->len != chan->sdu_len)
    1205:	48 8b b3 b8 00 00 00 	mov    0xb8(%rbx),%rsi
    120c:	0f b7 83 b0 00 00 00 	movzwl 0xb0(%rbx),%eax
    1213:	39 46 68             	cmp    %eax,0x68(%rsi)
    1216:	0f 85 5c 01 00 00    	jne    1378 <l2cap_reassemble_sdu+0x258>
		err = chan->ops->recv(chan->data, chan->sdu);
    121c:	48 8b 83 40 03 00 00 	mov    0x340(%rbx),%rax
    1223:	48 8b bb 38 03 00 00 	mov    0x338(%rbx),%rdi
    122a:	ff 50 10             	callq  *0x10(%rax)
		if (!err) {
    122d:	85 c0                	test   %eax,%eax
    122f:	0f 85 53 01 00 00    	jne    1388 <l2cap_reassemble_sdu+0x268>
			chan->sdu_len = 0;
    1235:	31 d2                	xor    %edx,%edx
			chan->sdu = NULL;
    1237:	48 c7 83 b8 00 00 00 	movq   $0x0,0xb8(%rbx)
    123e:	00 00 00 00 
			chan->sdu_last_frag = NULL;
    1242:	48 c7 83 c0 00 00 00 	movq   $0x0,0xc0(%rbx)
    1249:	00 00 00 00 
			chan->sdu_len = 0;
    124d:	66 89 93 b0 00 00 00 	mov    %dx,0xb0(%rbx)
{
    1254:	31 c0                	xor    %eax,%eax
}
    1256:	48 83 c4 10          	add    $0x10,%rsp
    125a:	5b                   	pop    %rbx
    125b:	41 5c                	pop    %r12
    125d:	5d                   	pop    %rbp
    125e:	c3                   	retq   
    125f:	90                   	nop
		if (chan->sdu)
    1260:	48 83 bb b8 00 00 00 	cmpq   $0x0,0xb8(%rbx)
    1267:	00 
    1268:	75 5e                	jne    12c8 <l2cap_reassemble_sdu+0x1a8>
    126a:	49 8b 84 24 e0 00 00 	mov    0xe0(%r12),%rax
    1271:	00 
		skb_pull(skb, L2CAP_SDULEN_SIZE);
    1272:	be 02 00 00 00       	mov    $0x2,%esi
    1277:	4c 89 e7             	mov    %r12,%rdi
    127a:	0f b7 00             	movzwl (%rax),%eax
		chan->sdu_len = get_unaligned_le16(skb->data);
    127d:	66 89 83 b0 00 00 00 	mov    %ax,0xb0(%rbx)
		skb_pull(skb, L2CAP_SDULEN_SIZE);
    1284:	e8 00 00 00 00       	callq  1289 <l2cap_reassemble_sdu+0x169>
		if (chan->sdu_len > chan->imtu) {
    1289:	0f b7 83 b0 00 00 00 	movzwl 0xb0(%rbx),%eax
    1290:	66 3b 43 1e          	cmp    0x1e(%rbx),%ax
    1294:	0f 87 0f 01 00 00    	ja     13a9 <l2cap_reassemble_sdu+0x289>
		if (skb->len >= chan->sdu_len)
    129a:	41 39 44 24 68       	cmp    %eax,0x68(%r12)
    129f:	73 27                	jae    12c8 <l2cap_reassemble_sdu+0x1a8>
		chan->sdu = skb;
    12a1:	4c 89 a3 b8 00 00 00 	mov    %r12,0xb8(%rbx)
		chan->sdu_last_frag = skb;
    12a8:	4c 89 a3 c0 00 00 00 	mov    %r12,0xc0(%rbx)
{
    12af:	31 c0                	xor    %eax,%eax
    12b1:	eb a3                	jmp    1256 <l2cap_reassemble_sdu+0x136>
    12b3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		if (!chan->sdu)
    12b8:	48 8b 83 b8 00 00 00 	mov    0xb8(%rbx),%rax
    12bf:	48 85 c0             	test   %rax,%rax
    12c2:	75 4c                	jne    1310 <l2cap_reassemble_sdu+0x1f0>
    12c4:	0f 1f 40 00          	nopl   0x0(%rax)
	int err = -EINVAL;
    12c8:	b8 ea ff ff ff       	mov    $0xffffffea,%eax
		kfree_skb(skb);
    12cd:	4c 89 e7             	mov    %r12,%rdi
    12d0:	89 45 ec             	mov    %eax,-0x14(%rbp)
    12d3:	e8 00 00 00 00       	callq  12d8 <l2cap_reassemble_sdu+0x1b8>
		kfree_skb(chan->sdu);
    12d8:	48 8b bb b8 00 00 00 	mov    0xb8(%rbx),%rdi
    12df:	e8 00 00 00 00       	callq  12e4 <l2cap_reassemble_sdu+0x1c4>
		chan->sdu_len = 0;
    12e4:	31 c0                	xor    %eax,%eax
		chan->sdu = NULL;
    12e6:	48 c7 83 b8 00 00 00 	movq   $0x0,0xb8(%rbx)
    12ed:	00 00 00 00 
		chan->sdu_last_frag = NULL;
    12f1:	48 c7 83 c0 00 00 00 	movq   $0x0,0xc0(%rbx)
    12f8:	00 00 00 00 
		chan->sdu_len = 0;
    12fc:	66 89 83 b0 00 00 00 	mov    %ax,0xb0(%rbx)
    1303:	8b 45 ec             	mov    -0x14(%rbp),%eax
}
    1306:	48 83 c4 10          	add    $0x10,%rsp
    130a:	5b                   	pop    %rbx
    130b:	41 5c                	pop    %r12
    130d:	5d                   	pop    %rbp
    130e:	c3                   	retq   
    130f:	90                   	nop
    1310:	8b 90 d0 00 00 00    	mov    0xd0(%rax),%edx
    1316:	48 03 90 d8 00 00 00 	add    0xd8(%rax),%rdx
	if (!skb_has_frag_list(skb))
    131d:	48 83 7a 08 00       	cmpq   $0x0,0x8(%rdx)
    1322:	74 7c                	je     13a0 <l2cap_reassemble_sdu+0x280>
	new_frag->next = NULL;
    1324:	49 c7 04 24 00 00 00 	movq   $0x0,(%r12)
    132b:	00 
	(*last_frag)->next = new_frag;
    132c:	48 8b 93 c0 00 00 00 	mov    0xc0(%rbx),%rdx
    1333:	4c 89 22             	mov    %r12,(%rdx)
	*last_frag = new_frag;
    1336:	4c 89 a3 c0 00 00 00 	mov    %r12,0xc0(%rbx)
	skb->len += new_frag->len;
    133d:	41 8b 54 24 68       	mov    0x68(%r12),%edx
    1342:	01 50 68             	add    %edx,0x68(%rax)
	skb->data_len += new_frag->len;
    1345:	41 8b 54 24 68       	mov    0x68(%r12),%edx
    134a:	01 50 6c             	add    %edx,0x6c(%rax)
	skb->truesize += new_frag->truesize;
    134d:	41 8b 94 24 e8 00 00 	mov    0xe8(%r12),%edx
    1354:	00 
    1355:	01 90 e8 00 00 00    	add    %edx,0xe8(%rax)
		if (chan->sdu->len >= chan->sdu_len)
    135b:	48 8b 93 b8 00 00 00 	mov    0xb8(%rbx),%rdx
    1362:	0f b7 83 b0 00 00 00 	movzwl 0xb0(%rbx),%eax
    1369:	39 42 68             	cmp    %eax,0x68(%rdx)
    136c:	0f 82 e2 fe ff ff    	jb     1254 <l2cap_reassemble_sdu+0x134>
    1372:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
	int err = -EINVAL;
    1378:	b8 ea ff ff ff       	mov    $0xffffffea,%eax
		skb = NULL;
    137d:	45 31 e4             	xor    %r12d,%r12d
    1380:	e9 48 ff ff ff       	jmpq   12cd <l2cap_reassemble_sdu+0x1ad>
    1385:	0f 1f 00             	nopl   (%rax)
		skb = NULL;
    1388:	45 31 e4             	xor    %r12d,%r12d
    138b:	e9 3d ff ff ff       	jmpq   12cd <l2cap_reassemble_sdu+0x1ad>
		skb_shinfo(skb)->frag_list = new_frag;
    1390:	4c 89 62 08          	mov    %r12,0x8(%rdx)
    1394:	e9 35 fe ff ff       	jmpq   11ce <l2cap_reassemble_sdu+0xae>
    1399:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    13a0:	4c 89 62 08          	mov    %r12,0x8(%rdx)
    13a4:	e9 7b ff ff ff       	jmpq   1324 <l2cap_reassemble_sdu+0x204>
			err = -EMSGSIZE;
    13a9:	b8 a6 ff ff ff       	mov    $0xffffffa6,%eax
    13ae:	e9 1a ff ff ff       	jmpq   12cd <l2cap_reassemble_sdu+0x1ad>
    13b3:	0f 1f 00             	nopl   (%rax)
    13b6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    13bd:	00 00 00 

00000000000013c0 <l2cap_send_cmd>:
{
    13c0:	55                   	push   %rbp
    13c1:	48 89 e5             	mov    %rsp,%rbp
    13c4:	41 57                	push   %r15
    13c6:	41 56                	push   %r14
    13c8:	41 55                	push   %r13
    13ca:	41 54                	push   %r12
    13cc:	53                   	push   %rbx
    13cd:	48 83 ec 28          	sub    $0x28,%rsp
    13d1:	e8 00 00 00 00       	callq  13d6 <l2cap_send_cmd+0x16>
	BT_DBG("conn %p, code 0x%2.2x, ident 0x%2.2x, len %d",
    13d6:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 13dd <l2cap_send_cmd+0x1d>
	struct sk_buff *skb = l2cap_build_cmd(conn, code, ident, len, data);
    13dd:	0f b6 c2             	movzbl %dl,%eax
{
    13e0:	49 89 ff             	mov    %rdi,%r15
    13e3:	89 75 bc             	mov    %esi,-0x44(%rbp)
    13e6:	41 89 d6             	mov    %edx,%r14d
    13e9:	41 89 cc             	mov    %ecx,%r12d
    13ec:	4c 89 45 c8          	mov    %r8,-0x38(%rbp)
	struct sk_buff *skb = l2cap_build_cmd(conn, code, ident, len, data);
    13f0:	89 45 b4             	mov    %eax,-0x4c(%rbp)
	BT_DBG("conn %p, code 0x%2.2x, ident 0x%2.2x, len %d",
    13f3:	0f b7 d9             	movzwl %cx,%ebx
    13f6:	0f 85 c6 01 00 00    	jne    15c2 <l2cap_send_cmd+0x202>
	count = min_t(unsigned int, conn->mtu, len);
    13fc:	41 8b 47 20          	mov    0x20(%r15),%eax
	len = L2CAP_HDR_SIZE + L2CAP_CMD_HDR_SIZE + dlen;
    1400:	83 c3 08             	add    $0x8,%ebx
	return __alloc_skb(size, priority, 0, NUMA_NO_NODE);
    1403:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    1408:	be 20 00 00 00       	mov    $0x20,%esi
	count = min_t(unsigned int, conn->mtu, len);
    140d:	39 c3                	cmp    %eax,%ebx
    140f:	0f 46 c3             	cmovbe %ebx,%eax
    1412:	31 d2                	xor    %edx,%edx

static inline struct sk_buff *bt_skb_alloc(unsigned int len, gfp_t how)
{
	struct sk_buff *skb;

	if ((skb = alloc_skb(len + BT_SKB_RESERVE, how))) {
    1414:	8d 78 08             	lea    0x8(%rax),%edi
    1417:	89 45 b8             	mov    %eax,-0x48(%rbp)
    141a:	e8 00 00 00 00       	callq  141f <l2cap_send_cmd+0x5f>
    141f:	48 85 c0             	test   %rax,%rax
    1422:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    1426:	49 89 c5             	mov    %rax,%r13
    1429:	0f 84 0b 01 00 00    	je     153a <l2cap_send_cmd+0x17a>
 *	Increase the headroom of an empty &sk_buff by reducing the tail
 *	room. This is only allowed for an empty buffer.
 */
static inline void skb_reserve(struct sk_buff *skb, int len)
{
	skb->data += len;
    142f:	48 83 80 e0 00 00 00 	addq   $0x8,0xe0(%rax)
    1436:	08 
	skb->tail += len;
    1437:	83 80 cc 00 00 00 08 	addl   $0x8,0xcc(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    143e:	be 04 00 00 00       	mov    $0x4,%esi
    1443:	48 89 c7             	mov    %rax,%rdi
		skb_reserve(skb, BT_SKB_RESERVE);
		bt_cb(skb)->incoming  = 0;
    1446:	c6 40 29 00          	movb   $0x0,0x29(%rax)
    144a:	e8 00 00 00 00       	callq  144f <l2cap_send_cmd+0x8f>
	lh->len = cpu_to_le16(L2CAP_CMD_HDR_SIZE + dlen);
    144f:	41 8d 54 24 04       	lea    0x4(%r12),%edx
	cmd = (struct l2cap_cmd_hdr *) skb_put(skb, L2CAP_CMD_HDR_SIZE);
    1454:	be 04 00 00 00       	mov    $0x4,%esi
    1459:	4c 89 ef             	mov    %r13,%rdi
	lh->len = cpu_to_le16(L2CAP_CMD_HDR_SIZE + dlen);
    145c:	66 89 10             	mov    %dx,(%rax)
	if (conn->hcon->type == LE_LINK)
    145f:	49 8b 17             	mov    (%r15),%rdx
		lh->cid = cpu_to_le16(L2CAP_CID_LE_SIGNALING);
    1462:	80 7a 21 80          	cmpb   $0x80,0x21(%rdx)
    1466:	0f 94 c2             	sete   %dl
    1469:	0f b6 d2             	movzbl %dl,%edx
    146c:	8d 14 95 01 00 00 00 	lea    0x1(,%rdx,4),%edx
    1473:	66 89 50 02          	mov    %dx,0x2(%rax)
	cmd = (struct l2cap_cmd_hdr *) skb_put(skb, L2CAP_CMD_HDR_SIZE);
    1477:	e8 00 00 00 00       	callq  147c <l2cap_send_cmd+0xbc>
	cmd->ident = ident;
    147c:	0f b6 4d bc          	movzbl -0x44(%rbp),%ecx
	if (dlen) {
    1480:	66 45 85 e4          	test   %r12w,%r12w
	cmd->code  = code;
    1484:	44 88 30             	mov    %r14b,(%rax)
	cmd->len   = cpu_to_le16(dlen);
    1487:	66 44 89 60 02       	mov    %r12w,0x2(%rax)
	cmd->ident = ident;
    148c:	88 48 01             	mov    %cl,0x1(%rax)
	if (dlen) {
    148f:	0f 85 03 01 00 00    	jne    1598 <l2cap_send_cmd+0x1d8>
	return skb->head + skb->end;
    1495:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    1499:	44 8b a0 d0 00 00 00 	mov    0xd0(%rax),%r12d
    14a0:	4c 03 a0 d8 00 00 00 	add    0xd8(%rax),%r12
	frag = &skb_shinfo(skb)->frag_list;
    14a7:	49 83 c4 08          	add    $0x8,%r12
	while (len) {
    14ab:	2b 58 68             	sub    0x68(%rax),%ebx
    14ae:	75 49                	jne    14f9 <l2cap_send_cmd+0x139>
    14b0:	e9 85 00 00 00       	jmpq   153a <l2cap_send_cmd+0x17a>
    14b5:	0f 1f 00             	nopl   (%rax)
	skb->data += len;
    14b8:	48 83 80 e0 00 00 00 	addq   $0x8,0xe0(%rax)
    14bf:	08 
	skb->tail += len;
    14c0:	83 80 cc 00 00 00 08 	addl   $0x8,0xcc(%rax)
		memcpy(skb_put(*frag, count), data, count);
    14c7:	44 89 ee             	mov    %r13d,%esi
    14ca:	c6 40 29 00          	movb   $0x0,0x29(%rax)
    14ce:	48 89 c7             	mov    %rax,%rdi
		*frag = bt_skb_alloc(count, GFP_ATOMIC);
    14d1:	49 89 04 24          	mov    %rax,(%r12)
		memcpy(skb_put(*frag, count), data, count);
    14d5:	4d 63 f5             	movslq %r13d,%r14
    14d8:	e8 00 00 00 00       	callq  14dd <l2cap_send_cmd+0x11d>
    14dd:	48 8b 75 c8          	mov    -0x38(%rbp),%rsi
    14e1:	4c 89 f2             	mov    %r14,%rdx
    14e4:	48 89 c7             	mov    %rax,%rdi
    14e7:	e8 00 00 00 00       	callq  14ec <l2cap_send_cmd+0x12c>
		data += count;
    14ec:	4c 01 75 c8          	add    %r14,-0x38(%rbp)
	while (len) {
    14f0:	44 29 eb             	sub    %r13d,%ebx
		frag = &(*frag)->next;
    14f3:	4d 8b 24 24          	mov    (%r12),%r12
	while (len) {
    14f7:	74 41                	je     153a <l2cap_send_cmd+0x17a>
		count = min_t(unsigned int, conn->mtu, len);
    14f9:	45 8b 47 20          	mov    0x20(%r15),%r8d
	return __alloc_skb(size, priority, 0, NUMA_NO_NODE);
    14fd:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    1502:	be 20 00 00 00       	mov    $0x20,%esi
    1507:	44 39 c3             	cmp    %r8d,%ebx
    150a:	44 0f 46 c3          	cmovbe %ebx,%r8d
    150e:	31 d2                	xor    %edx,%edx
	if ((skb = alloc_skb(len + BT_SKB_RESERVE, how))) {
    1510:	41 8d 78 08          	lea    0x8(%r8),%edi
    1514:	45 89 c5             	mov    %r8d,%r13d
    1517:	e8 00 00 00 00       	callq  151c <l2cap_send_cmd+0x15c>
    151c:	48 85 c0             	test   %rax,%rax
    151f:	75 97                	jne    14b8 <l2cap_send_cmd+0xf8>
	kfree_skb(skb);
    1521:	48 8b 7d c0          	mov    -0x40(%rbp),%rdi
		*frag = bt_skb_alloc(count, GFP_ATOMIC);
    1525:	49 c7 04 24 00 00 00 	movq   $0x0,(%r12)
    152c:	00 
	kfree_skb(skb);
    152d:	e8 00 00 00 00       	callq  1532 <l2cap_send_cmd+0x172>
	return NULL;
    1532:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
    1539:	00 
	BT_DBG("code 0x%2.2x", code);
    153a:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 1541 <l2cap_send_cmd+0x181>
    1541:	0f 85 a3 00 00 00    	jne    15ea <l2cap_send_cmd+0x22a>
	if (!skb)
    1547:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
    154b:	48 85 c9             	test   %rcx,%rcx
    154e:	74 32                	je     1582 <l2cap_send_cmd+0x1c2>
	if (lmp_no_flush_capable(conn->hcon->hdev))
    1550:	49 8b 07             	mov    (%r15),%rax
	hci_send_acl(conn->hchan, skb, flags);
    1553:	48 89 ce             	mov    %rcx,%rsi
	if (lmp_no_flush_capable(conn->hcon->hdev))
    1556:	48 8b 80 18 04 00 00 	mov    0x418(%rax),%rax
    155d:	0f b6 80 47 02 00 00 	movzbl 0x247(%rax),%eax
	bt_cb(skb)->force_active = BT_POWER_FORCE_ACTIVE_ON;
    1564:	c6 41 2c 01          	movb   $0x1,0x2c(%rcx)
	skb->priority = HCI_PRIO_MAX;
    1568:	c7 41 78 07 00 00 00 	movl   $0x7,0x78(%rcx)
	hci_send_acl(conn->hchan, skb, flags);
    156f:	49 8b 7f 08          	mov    0x8(%r15),%rdi
	if (lmp_no_flush_capable(conn->hcon->hdev))
    1573:	83 e0 40             	and    $0x40,%eax
    1576:	3c 01                	cmp    $0x1,%al
    1578:	19 d2                	sbb    %edx,%edx
    157a:	83 e2 02             	and    $0x2,%edx
	hci_send_acl(conn->hchan, skb, flags);
    157d:	e8 00 00 00 00       	callq  1582 <l2cap_send_cmd+0x1c2>
}
    1582:	48 83 c4 28          	add    $0x28,%rsp
    1586:	5b                   	pop    %rbx
    1587:	41 5c                	pop    %r12
    1589:	41 5d                	pop    %r13
    158b:	41 5e                	pop    %r14
    158d:	41 5f                	pop    %r15
    158f:	5d                   	pop    %rbp
    1590:	c3                   	retq   
    1591:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		count -= L2CAP_HDR_SIZE + L2CAP_CMD_HDR_SIZE;
    1598:	8b 75 b8             	mov    -0x48(%rbp),%esi
		memcpy(skb_put(skb, count), data, count);
    159b:	48 8b 7d c0          	mov    -0x40(%rbp),%rdi
		count -= L2CAP_HDR_SIZE + L2CAP_CMD_HDR_SIZE;
    159f:	83 ee 08             	sub    $0x8,%esi
		memcpy(skb_put(skb, count), data, count);
    15a2:	4c 63 e6             	movslq %esi,%r12
    15a5:	e8 00 00 00 00       	callq  15aa <l2cap_send_cmd+0x1ea>
    15aa:	48 8b 75 c8          	mov    -0x38(%rbp),%rsi
    15ae:	4c 89 e2             	mov    %r12,%rdx
    15b1:	48 89 c7             	mov    %rax,%rdi
    15b4:	e8 00 00 00 00       	callq  15b9 <l2cap_send_cmd+0x1f9>
		data += count;
    15b9:	4c 01 65 c8          	add    %r12,-0x38(%rbp)
    15bd:	e9 d3 fe ff ff       	jmpq   1495 <l2cap_send_cmd+0xd5>
	BT_DBG("conn %p, code 0x%2.2x, ident 0x%2.2x, len %d",
    15c2:	44 0f b6 45 bc       	movzbl -0x44(%rbp),%r8d
    15c7:	8b 4d b4             	mov    -0x4c(%rbp),%ecx
    15ca:	48 89 fa             	mov    %rdi,%rdx
    15cd:	41 89 d9             	mov    %ebx,%r9d
    15d0:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    15d7:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    15de:	31 c0                	xor    %eax,%eax
    15e0:	e8 00 00 00 00       	callq  15e5 <l2cap_send_cmd+0x225>
    15e5:	e9 12 fe ff ff       	jmpq   13fc <l2cap_send_cmd+0x3c>
	BT_DBG("code 0x%2.2x", code);
    15ea:	8b 55 b4             	mov    -0x4c(%rbp),%edx
    15ed:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    15f4:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    15fb:	31 c0                	xor    %eax,%eax
    15fd:	e8 00 00 00 00       	callq  1602 <l2cap_send_cmd+0x242>
    1602:	e9 40 ff ff ff       	jmpq   1547 <l2cap_send_cmd+0x187>
    1607:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    160e:	00 00 

0000000000001610 <l2cap_send_conn_req>:
{
    1610:	55                   	push   %rbp
    1611:	48 89 e5             	mov    %rsp,%rbp
    1614:	41 54                	push   %r12
    1616:	53                   	push   %rbx
    1617:	48 83 ec 10          	sub    $0x10,%rsp
    161b:	e8 00 00 00 00       	callq  1620 <l2cap_send_conn_req+0x10>
	req.scid = cpu_to_le16(chan->scid);
    1620:	0f b7 47 1c          	movzwl 0x1c(%rdi),%eax
	struct l2cap_conn *conn = chan->conn;
    1624:	4c 8b 67 08          	mov    0x8(%rdi),%r12
{
    1628:	48 89 fb             	mov    %rdi,%rbx
	req.scid = cpu_to_le16(chan->scid);
    162b:	66 89 45 ee          	mov    %ax,-0x12(%rbp)
	req.psm  = chan->psm;
    162f:	0f b7 47 18          	movzwl 0x18(%rdi),%eax
	chan->ident = l2cap_get_ident(conn);
    1633:	4c 89 e7             	mov    %r12,%rdi
	req.psm  = chan->psm;
    1636:	66 89 45 ec          	mov    %ax,-0x14(%rbp)
	chan->ident = l2cap_get_ident(conn);
    163a:	e8 71 ee ff ff       	callq  4b0 <l2cap_get_ident>
    163f:	88 43 2b             	mov    %al,0x2b(%rbx)
		asm volatile(LOCK_PREFIX "orb %1,%0"
    1642:	f0 80 8b 80 00 00 00 	lock orb $0x20,0x80(%rbx)
    1649:	20 
	l2cap_send_cmd(conn, chan->ident, L2CAP_CONN_REQ, sizeof(req), &req);
    164a:	0f b6 73 2b          	movzbl 0x2b(%rbx),%esi
    164e:	4c 8d 45 ec          	lea    -0x14(%rbp),%r8
    1652:	4c 89 e7             	mov    %r12,%rdi
    1655:	b9 04 00 00 00       	mov    $0x4,%ecx
    165a:	ba 02 00 00 00       	mov    $0x2,%edx
    165f:	e8 5c fd ff ff       	callq  13c0 <l2cap_send_cmd>
}
    1664:	48 83 c4 10          	add    $0x10,%rsp
    1668:	5b                   	pop    %rbx
    1669:	41 5c                	pop    %r12
    166b:	5d                   	pop    %rbp
    166c:	c3                   	retq   
    166d:	0f 1f 00             	nopl   (%rax)

0000000000001670 <l2cap_build_conf_req>:
{
    1670:	55                   	push   %rbp
    1671:	48 89 e5             	mov    %rsp,%rbp
    1674:	41 55                	push   %r13
    1676:	41 54                	push   %r12
    1678:	53                   	push   %rbx
    1679:	48 83 ec 28          	sub    $0x28,%rsp
    167d:	e8 00 00 00 00       	callq  1682 <l2cap_build_conf_req+0x12>
	struct l2cap_conf_rfc rfc = { .mode = chan->mode };
    1682:	0f b6 47 24          	movzbl 0x24(%rdi),%eax
	BT_DBG("chan %p", chan);
    1686:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 168d <l2cap_build_conf_req+0x1d>
	struct l2cap_conf_rfc rfc = { .mode = chan->mode };
    168d:	48 c7 45 d7 00 00 00 	movq   $0x0,-0x29(%rbp)
    1694:	00 
{
    1695:	48 89 fb             	mov    %rdi,%rbx
    1698:	49 89 f4             	mov    %rsi,%r12
	struct l2cap_conf_rfc rfc = { .mode = chan->mode };
    169b:	c6 45 df 00          	movb   $0x0,-0x21(%rbp)
    169f:	88 45 d7             	mov    %al,-0x29(%rbp)
	void *ptr = req->data;
    16a2:	48 8d 46 04          	lea    0x4(%rsi),%rax
    16a6:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
	BT_DBG("chan %p", chan);
    16aa:	0f 85 3a 03 00 00    	jne    19ea <l2cap_build_conf_req+0x37a>
	if (chan->num_conf_req || chan->num_conf_rsp)
    16b0:	f7 43 6c 00 ff ff 00 	testl  $0xffff00,0x6c(%rbx)
    16b7:	75 50                	jne    1709 <l2cap_build_conf_req+0x99>
	switch (chan->mode) {
    16b9:	0f b6 43 24          	movzbl 0x24(%rbx),%eax
    16bd:	83 e8 03             	sub    $0x3,%eax
    16c0:	3c 01                	cmp    $0x1,%al
    16c2:	0f 86 a0 00 00 00    	jbe    1768 <l2cap_build_conf_req+0xf8>
    16c8:	48 8b 43 08          	mov    0x8(%rbx),%rax
    16cc:	8b 70 24             	mov    0x24(%rax),%esi
		chan->mode = l2cap_select_mode(rfc.mode, chan->conn->feat_mask);
    16cf:	0f b6 55 d7          	movzbl -0x29(%rbp),%edx
		return L2CAP_MODE_BASIC;
    16d3:	31 c0                	xor    %eax,%eax
	switch (mode) {
    16d5:	8d 4a fd             	lea    -0x3(%rdx),%ecx
    16d8:	80 f9 01             	cmp    $0x1,%cl
    16db:	77 29                	ja     1706 <l2cap_build_conf_req+0x96>
	u32 local_feat_mask = l2cap_feat_mask;
    16dd:	80 3d 00 00 00 00 01 	cmpb   $0x1,0x0(%rip)        # 16e4 <l2cap_build_conf_req+0x74>
    16e4:	0f b7 f6             	movzwl %si,%esi
    16e7:	19 c0                	sbb    %eax,%eax
    16e9:	83 e0 18             	and    $0x18,%eax
    16ec:	83 e8 80             	sub    $0xffffff80,%eax
		return L2CAP_FEAT_STREAMING & feat_mask & local_feat_mask;
    16ef:	21 f0                	and    %esi,%eax
	switch (mode) {
    16f1:	80 fa 04             	cmp    $0x4,%dl
		return L2CAP_FEAT_STREAMING & feat_mask & local_feat_mask;
    16f4:	89 c1                	mov    %eax,%ecx
	switch (mode) {
    16f6:	0f 85 c4 02 00 00    	jne    19c0 <l2cap_build_conf_req+0x350>
		return L2CAP_FEAT_STREAMING & feat_mask & local_feat_mask;
    16fc:	83 e1 10             	and    $0x10,%ecx
		return L2CAP_MODE_BASIC;
    16ff:	31 c0                	xor    %eax,%eax
    1701:	85 c9                	test   %ecx,%ecx
    1703:	0f 45 c2             	cmovne %edx,%eax
		chan->mode = l2cap_select_mode(rfc.mode, chan->conn->feat_mask);
    1706:	88 43 24             	mov    %al,0x24(%rbx)
	if (chan->imtu != L2CAP_DEFAULT_MTU)
    1709:	0f b7 4b 1e          	movzwl 0x1e(%rbx),%ecx
    170d:	66 81 f9 a0 02       	cmp    $0x2a0,%cx
    1712:	74 13                	je     1727 <l2cap_build_conf_req+0xb7>
		l2cap_add_conf_opt(&ptr, L2CAP_CONF_MTU, 2, chan->imtu);
    1714:	48 8d 7d c8          	lea    -0x38(%rbp),%rdi
    1718:	ba 02 00 00 00       	mov    $0x2,%edx
    171d:	be 01 00 00 00       	mov    $0x1,%esi
    1722:	e8 89 ee ff ff       	callq  5b0 <l2cap_add_conf_opt>
	switch (chan->mode) {
    1727:	0f b6 43 24          	movzbl 0x24(%rbx),%eax
    172b:	3c 03                	cmp    $0x3,%al
    172d:	0f 84 5d 01 00 00    	je     1890 <l2cap_build_conf_req+0x220>
    1733:	3c 04                	cmp    $0x4,%al
    1735:	0f 84 b5 00 00 00    	je     17f0 <l2cap_build_conf_req+0x180>
    173b:	84 c0                	test   %al,%al
    173d:	74 61                	je     17a0 <l2cap_build_conf_req+0x130>
	req->dcid  = cpu_to_le16(chan->dcid);
    173f:	0f b7 43 1a          	movzwl 0x1a(%rbx),%eax
    1743:	66 41 89 04 24       	mov    %ax,(%r12)
	req->flags = cpu_to_le16(0);
    1748:	31 c0                	xor    %eax,%eax
    174a:	66 41 89 44 24 02    	mov    %ax,0x2(%r12)
	return ptr - data;
    1750:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
}
    1754:	48 83 c4 28          	add    $0x28,%rsp
    1758:	5b                   	pop    %rbx
	return ptr - data;
    1759:	4c 29 e0             	sub    %r12,%rax
}
    175c:	41 5c                	pop    %r12
    175e:	41 5d                	pop    %r13
    1760:	5d                   	pop    %rbp
    1761:	c3                   	retq   
    1762:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		(addr[nr / BITS_PER_LONG])) != 0;
    1768:	48 8b 83 80 00 00 00 	mov    0x80(%rbx),%rax
		if (test_bit(CONF_STATE2_DEVICE, &chan->conf_state))
    176f:	a8 80                	test   $0x80,%al
    1771:	75 96                	jne    1709 <l2cap_build_conf_req+0x99>
	return enable_hs && chan->conn->feat_mask & L2CAP_FEAT_EXT_FLOW;
    1773:	80 3d 00 00 00 00 00 	cmpb   $0x0,0x0(%rip)        # 177a <l2cap_build_conf_req+0x10a>
    177a:	48 8b 43 08          	mov    0x8(%rbx),%rax
    177e:	8b 70 24             	mov    0x24(%rax),%esi
    1781:	0f 84 48 ff ff ff    	je     16cf <l2cap_build_conf_req+0x5f>
    1787:	40 f6 c6 40          	test   $0x40,%sil
    178b:	0f 84 3e ff ff ff    	je     16cf <l2cap_build_conf_req+0x5f>
		asm volatile(LOCK_PREFIX "orb %1,%0"
    1791:	f0 80 8b 90 00 00 00 	lock orb $0x20,0x90(%rbx)
    1798:	20 
    1799:	e9 2a ff ff ff       	jmpq   16c8 <l2cap_build_conf_req+0x58>
    179e:	66 90                	xchg   %ax,%ax
		if (!(chan->conn->feat_mask & L2CAP_FEAT_ERTM) &&
    17a0:	48 8b 43 08          	mov    0x8(%rbx),%rax
    17a4:	f6 40 24 18          	testb  $0x18,0x24(%rax)
    17a8:	74 95                	je     173f <l2cap_build_conf_req+0xcf>
		l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC, sizeof(rfc),
    17aa:	48 8d 4d d7          	lea    -0x29(%rbp),%rcx
    17ae:	48 8d 7d c8          	lea    -0x38(%rbp),%rdi
		rfc.retrans_timeout = 0;
    17b2:	45 31 d2             	xor    %r10d,%r10d
		rfc.monitor_timeout = 0;
    17b5:	45 31 db             	xor    %r11d,%r11d
		rfc.max_pdu_size    = 0;
    17b8:	45 31 ed             	xor    %r13d,%r13d
		l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC, sizeof(rfc),
    17bb:	ba 09 00 00 00       	mov    $0x9,%edx
    17c0:	be 04 00 00 00       	mov    $0x4,%esi
		rfc.mode            = L2CAP_MODE_BASIC;
    17c5:	c6 45 d7 00          	movb   $0x0,-0x29(%rbp)
		rfc.txwin_size      = 0;
    17c9:	c6 45 d8 00          	movb   $0x0,-0x28(%rbp)
		rfc.max_transmit    = 0;
    17cd:	c6 45 d9 00          	movb   $0x0,-0x27(%rbp)
		rfc.retrans_timeout = 0;
    17d1:	66 44 89 55 da       	mov    %r10w,-0x26(%rbp)
		rfc.monitor_timeout = 0;
    17d6:	66 44 89 5d dc       	mov    %r11w,-0x24(%rbp)
		rfc.max_pdu_size    = 0;
    17db:	66 44 89 6d de       	mov    %r13w,-0x22(%rbp)
		l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC, sizeof(rfc),
    17e0:	e8 cb ed ff ff       	callq  5b0 <l2cap_add_conf_opt>
		break;
    17e5:	e9 55 ff ff ff       	jmpq   173f <l2cap_build_conf_req+0xcf>
    17ea:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		size = min_t(u16, L2CAP_DEFAULT_MAX_PDU_SIZE, chan->conn->mtu -
    17f0:	48 8b 43 08          	mov    0x8(%rbx),%rax
		rfc.retrans_timeout = 0;
    17f4:	31 c9                	xor    %ecx,%ecx
		l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC, sizeof(rfc),
    17f6:	4c 8d 6d c8          	lea    -0x38(%rbp),%r13
		rfc.monitor_timeout = 0;
    17fa:	31 f6                	xor    %esi,%esi
		rfc.retrans_timeout = 0;
    17fc:	66 89 4d da          	mov    %cx,-0x26(%rbp)
		l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC, sizeof(rfc),
    1800:	48 8d 4d d7          	lea    -0x29(%rbp),%rcx
		rfc.monitor_timeout = 0;
    1804:	66 89 75 dc          	mov    %si,-0x24(%rbp)
		l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC, sizeof(rfc),
    1808:	4c 89 ef             	mov    %r13,%rdi
    180b:	be 04 00 00 00       	mov    $0x4,%esi
		size = min_t(u16, L2CAP_DEFAULT_MAX_PDU_SIZE, chan->conn->mtu -
    1810:	8b 50 20             	mov    0x20(%rax),%edx
    1813:	b8 f1 03 00 00       	mov    $0x3f1,%eax
		rfc.mode            = L2CAP_MODE_STREAMING;
    1818:	c6 45 d7 04          	movb   $0x4,-0x29(%rbp)
		rfc.txwin_size      = 0;
    181c:	c6 45 d8 00          	movb   $0x0,-0x28(%rbp)
		rfc.max_transmit    = 0;
    1820:	c6 45 d9 00          	movb   $0x0,-0x27(%rbp)
		size = min_t(u16, L2CAP_DEFAULT_MAX_PDU_SIZE, chan->conn->mtu -
    1824:	83 ea 0c             	sub    $0xc,%edx
    1827:	66 81 fa f1 03       	cmp    $0x3f1,%dx
    182c:	0f 46 c2             	cmovbe %edx,%eax
		l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC, sizeof(rfc),
    182f:	ba 09 00 00 00       	mov    $0x9,%edx
		rfc.max_pdu_size = cpu_to_le16(size);
    1834:	66 89 45 de          	mov    %ax,-0x22(%rbp)
		l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC, sizeof(rfc),
    1838:	e8 73 ed ff ff       	callq  5b0 <l2cap_add_conf_opt>
		(addr[nr / BITS_PER_LONG])) != 0;
    183d:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
		if (test_bit(FLAG_EFS_ENABLE, &chan->flags))
    1844:	a8 20                	test   $0x20,%al
    1846:	0f 85 64 01 00 00    	jne    19b0 <l2cap_build_conf_req+0x340>
		if (!(chan->conn->feat_mask & L2CAP_FEAT_FCS))
    184c:	48 8b 43 08          	mov    0x8(%rbx),%rax
    1850:	f6 40 24 20          	testb  $0x20,0x24(%rax)
    1854:	0f 84 e5 fe ff ff    	je     173f <l2cap_build_conf_req+0xcf>
		if (chan->fcs == L2CAP_FCS_NONE ||
    185a:	80 7b 6f 00          	cmpb   $0x0,0x6f(%rbx)
    185e:	74 0f                	je     186f <l2cap_build_conf_req+0x1ff>
    1860:	48 8b 83 80 00 00 00 	mov    0x80(%rbx),%rax
    1867:	a8 40                	test   $0x40,%al
    1869:	0f 84 d0 fe ff ff    	je     173f <l2cap_build_conf_req+0xcf>
			chan->fcs = L2CAP_FCS_NONE;
    186f:	c6 43 6f 00          	movb   $0x0,0x6f(%rbx)
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_FCS, 1, chan->fcs);
    1873:	31 c9                	xor    %ecx,%ecx
    1875:	ba 01 00 00 00       	mov    $0x1,%edx
    187a:	be 05 00 00 00       	mov    $0x5,%esi
    187f:	4c 89 ef             	mov    %r13,%rdi
    1882:	e8 29 ed ff ff       	callq  5b0 <l2cap_add_conf_opt>
    1887:	e9 b3 fe ff ff       	jmpq   173f <l2cap_build_conf_req+0xcf>
    188c:	0f 1f 40 00          	nopl   0x0(%rax)
		rfc.max_transmit    = chan->max_tx;
    1890:	0f b6 43 74          	movzbl 0x74(%rbx),%eax
		size = min_t(u16, L2CAP_DEFAULT_MAX_PDU_SIZE, chan->conn->mtu -
    1894:	48 8b 4b 08          	mov    0x8(%rbx),%rcx
		rfc.retrans_timeout = 0;
    1898:	45 31 c0             	xor    %r8d,%r8d
		rfc.monitor_timeout = 0;
    189b:	45 31 c9             	xor    %r9d,%r9d
		rfc.mode            = L2CAP_MODE_ERTM;
    189e:	c6 45 d7 03          	movb   $0x3,-0x29(%rbp)
		rfc.retrans_timeout = 0;
    18a2:	66 44 89 45 da       	mov    %r8w,-0x26(%rbp)
		rfc.monitor_timeout = 0;
    18a7:	66 44 89 4d dc       	mov    %r9w,-0x24(%rbp)
		rfc.max_transmit    = chan->max_tx;
    18ac:	88 45 d9             	mov    %al,-0x27(%rbp)
		size = min_t(u16, L2CAP_DEFAULT_MAX_PDU_SIZE, chan->conn->mtu -
    18af:	0f b7 41 20          	movzwl 0x20(%rcx),%eax
    18b3:	8d 50 f4             	lea    -0xc(%rax),%edx
    18b6:	b8 f1 03 00 00       	mov    $0x3f1,%eax
    18bb:	66 81 fa f1 03       	cmp    $0x3f1,%dx
    18c0:	0f 46 c2             	cmovbe %edx,%eax
	if (chan->tx_win > L2CAP_DEFAULT_TX_WINDOW &&
    18c3:	0f b7 53 70          	movzwl 0x70(%rbx),%edx
		rfc.max_pdu_size = cpu_to_le16(size);
    18c7:	66 89 45 de          	mov    %ax,-0x22(%rbp)
	if (chan->tx_win > L2CAP_DEFAULT_TX_WINDOW &&
    18cb:	66 83 fa 3f          	cmp    $0x3f,%dx
    18cf:	76 17                	jbe    18e8 <l2cap_build_conf_req+0x278>
	return enable_hs && chan->conn->feat_mask & L2CAP_FEAT_EXT_WINDOW;
    18d1:	80 3d 00 00 00 00 00 	cmpb   $0x0,0x0(%rip)        # 18d8 <l2cap_build_conf_req+0x268>
    18d8:	74 0e                	je     18e8 <l2cap_build_conf_req+0x278>
    18da:	f6 41 25 01          	testb  $0x1,0x25(%rcx)
    18de:	0f 85 ec 00 00 00    	jne    19d0 <l2cap_build_conf_req+0x360>
    18e4:	0f 1f 40 00          	nopl   0x0(%rax)
		chan->tx_win = min_t(u16, chan->tx_win,
    18e8:	b8 3f 00 00 00       	mov    $0x3f,%eax
    18ed:	66 83 fa 3f          	cmp    $0x3f,%dx
		chan->tx_win_max = L2CAP_DEFAULT_TX_WINDOW;
    18f1:	bf 3f 00 00 00       	mov    $0x3f,%edi
		chan->tx_win = min_t(u16, chan->tx_win,
    18f6:	0f 46 c2             	cmovbe %edx,%eax
		chan->tx_win_max = L2CAP_DEFAULT_TX_WINDOW;
    18f9:	66 89 7b 72          	mov    %di,0x72(%rbx)
		chan->tx_win = min_t(u16, chan->tx_win,
    18fd:	66 89 43 70          	mov    %ax,0x70(%rbx)
		rfc.txwin_size = min_t(u16, chan->tx_win,
    1901:	66 83 f8 3f          	cmp    $0x3f,%ax
    1905:	ba 3f 00 00 00       	mov    $0x3f,%edx
		l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC, sizeof(rfc),
    190a:	4c 8d 6d c8          	lea    -0x38(%rbp),%r13
		rfc.txwin_size = min_t(u16, chan->tx_win,
    190e:	0f 46 d0             	cmovbe %eax,%edx
		l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC, sizeof(rfc),
    1911:	48 8d 4d d7          	lea    -0x29(%rbp),%rcx
    1915:	be 04 00 00 00       	mov    $0x4,%esi
		rfc.txwin_size = min_t(u16, chan->tx_win,
    191a:	88 55 d8             	mov    %dl,-0x28(%rbp)
		l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC, sizeof(rfc),
    191d:	4c 89 ef             	mov    %r13,%rdi
    1920:	ba 09 00 00 00       	mov    $0x9,%edx
    1925:	e8 86 ec ff ff       	callq  5b0 <l2cap_add_conf_opt>
    192a:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
		if (test_bit(FLAG_EFS_ENABLE, &chan->flags))
    1931:	a8 20                	test   $0x20,%al
    1933:	75 6b                	jne    19a0 <l2cap_build_conf_req+0x330>
		if (!(chan->conn->feat_mask & L2CAP_FEAT_FCS))
    1935:	48 8b 43 08          	mov    0x8(%rbx),%rax
    1939:	f6 40 24 20          	testb  $0x20,0x24(%rax)
    193d:	0f 84 fc fd ff ff    	je     173f <l2cap_build_conf_req+0xcf>
		if (chan->fcs == L2CAP_FCS_NONE ||
    1943:	80 7b 6f 00          	cmpb   $0x0,0x6f(%rbx)
    1947:	74 0b                	je     1954 <l2cap_build_conf_req+0x2e4>
    1949:	48 8b 83 80 00 00 00 	mov    0x80(%rbx),%rax
    1950:	a8 40                	test   $0x40,%al
    1952:	74 18                	je     196c <l2cap_build_conf_req+0x2fc>
			chan->fcs = L2CAP_FCS_NONE;
    1954:	c6 43 6f 00          	movb   $0x0,0x6f(%rbx)
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_FCS, 1, chan->fcs);
    1958:	31 c9                	xor    %ecx,%ecx
    195a:	ba 01 00 00 00       	mov    $0x1,%edx
    195f:	be 05 00 00 00       	mov    $0x5,%esi
    1964:	4c 89 ef             	mov    %r13,%rdi
    1967:	e8 44 ec ff ff       	callq  5b0 <l2cap_add_conf_opt>
    196c:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
		if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    1973:	a8 10                	test   $0x10,%al
    1975:	0f 84 c4 fd ff ff    	je     173f <l2cap_build_conf_req+0xcf>
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_EWS, 2,
    197b:	0f b7 4b 70          	movzwl 0x70(%rbx),%ecx
    197f:	ba 02 00 00 00       	mov    $0x2,%edx
    1984:	be 07 00 00 00       	mov    $0x7,%esi
    1989:	4c 89 ef             	mov    %r13,%rdi
    198c:	e8 1f ec ff ff       	callq  5b0 <l2cap_add_conf_opt>
    1991:	e9 a9 fd ff ff       	jmpq   173f <l2cap_build_conf_req+0xcf>
    1996:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    199d:	00 00 00 
			l2cap_add_opt_efs(&ptr, chan);
    19a0:	48 89 de             	mov    %rbx,%rsi
    19a3:	4c 89 ef             	mov    %r13,%rdi
    19a6:	e8 d5 ec ff ff       	callq  680 <l2cap_add_opt_efs>
    19ab:	eb 88                	jmp    1935 <l2cap_build_conf_req+0x2c5>
    19ad:	0f 1f 00             	nopl   (%rax)
			l2cap_add_opt_efs(&ptr, chan);
    19b0:	48 89 de             	mov    %rbx,%rsi
    19b3:	4c 89 ef             	mov    %r13,%rdi
    19b6:	e8 c5 ec ff ff       	callq  680 <l2cap_add_opt_efs>
    19bb:	e9 8c fe ff ff       	jmpq   184c <l2cap_build_conf_req+0x1dc>
		return L2CAP_FEAT_ERTM & feat_mask & local_feat_mask;
    19c0:	83 e1 08             	and    $0x8,%ecx
    19c3:	e9 37 fd ff ff       	jmpq   16ff <l2cap_build_conf_req+0x8f>
    19c8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    19cf:	00 
		asm volatile(LOCK_PREFIX "orb %1,%0"
    19d0:	f0 80 8b 90 00 00 00 	lock orb $0x10,0x90(%rbx)
    19d7:	10 
		chan->tx_win_max = L2CAP_DEFAULT_EXT_WINDOW;
    19d8:	ba ff 3f 00 00       	mov    $0x3fff,%edx
    19dd:	0f b7 43 70          	movzwl 0x70(%rbx),%eax
    19e1:	66 89 53 72          	mov    %dx,0x72(%rbx)
    19e5:	e9 17 ff ff ff       	jmpq   1901 <l2cap_build_conf_req+0x291>
	BT_DBG("chan %p", chan);
    19ea:	48 89 fa             	mov    %rdi,%rdx
    19ed:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    19f4:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    19fb:	31 c0                	xor    %eax,%eax
    19fd:	e8 00 00 00 00       	callq  1a02 <l2cap_build_conf_req+0x392>
    1a02:	e9 a9 fc ff ff       	jmpq   16b0 <l2cap_build_conf_req+0x40>
    1a07:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    1a0e:	00 00 

0000000000001a10 <l2cap_parse_conf_req>:
{
    1a10:	55                   	push   %rbp
    1a11:	48 89 e5             	mov    %rsp,%rbp
    1a14:	41 57                	push   %r15
    1a16:	41 56                	push   %r14
    1a18:	41 55                	push   %r13
    1a1a:	41 54                	push   %r12
    1a1c:	53                   	push   %rbx
    1a1d:	48 83 ec 68          	sub    $0x68,%rsp
    1a21:	e8 00 00 00 00       	callq  1a26 <l2cap_parse_conf_req+0x16>
	int len = chan->conf_len;
    1a26:	0f b6 5f 6c          	movzbl 0x6c(%rdi),%ebx
{
    1a2a:	48 89 f0             	mov    %rsi,%rax
    1a2d:	49 89 fa             	mov    %rdi,%r10
    1a30:	48 89 75 88          	mov    %rsi,-0x78(%rbp)
	void *ptr = rsp->data;
    1a34:	48 83 c0 06          	add    $0x6,%rax
	BT_DBG("chan %p", chan);
    1a38:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 1a3f <l2cap_parse_conf_req+0x2f>
	void *req = chan->conf_req;
    1a3f:	4c 8d 4f 2c          	lea    0x2c(%rdi),%r9
	void *ptr = rsp->data;
    1a43:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
	struct l2cap_conf_rfc rfc = { .mode = L2CAP_MODE_BASIC };
    1a47:	48 c7 45 b7 00 00 00 	movq   $0x0,-0x49(%rbp)
    1a4e:	00 
    1a4f:	c6 45 bf 00          	movb   $0x0,-0x41(%rbp)
	BT_DBG("chan %p", chan);
    1a53:	0f 85 af 05 00 00    	jne    2008 <l2cap_parse_conf_req+0x5f8>
	while (len >= L2CAP_CONF_OPT_SIZE) {
    1a59:	45 31 f6             	xor    %r14d,%r14d
    1a5c:	83 fb 01             	cmp    $0x1,%ebx
    1a5f:	41 bb a0 02 00 00    	mov    $0x2a0,%r11d
    1a65:	66 44 89 75 98       	mov    %r14w,-0x68(%rbp)
    1a6a:	c6 45 90 00          	movb   $0x0,-0x70(%rbp)
    1a6e:	0f 8e ac 00 00 00    	jle    1b20 <l2cap_parse_conf_req+0x110>
    1a74:	0f 1f 40 00          	nopl   0x0(%rax)
	len = L2CAP_CONF_OPT_SIZE + opt->len;
    1a78:	41 0f b6 41 01       	movzbl 0x1(%r9),%eax
	*type = opt->type;
    1a7d:	45 0f b6 31          	movzbl (%r9),%r14d
	len = L2CAP_CONF_OPT_SIZE + opt->len;
    1a81:	44 0f b6 e8          	movzbl %al,%r13d
    1a85:	45 8d 65 02          	lea    0x2(%r13),%r12d
	*ptr += len;
    1a89:	4d 63 fc             	movslq %r12d,%r15
    1a8c:	4d 01 cf             	add    %r9,%r15
	switch (opt->len) {
    1a8f:	3c 02                	cmp    $0x2,%al
    1a91:	0f 84 e9 01 00 00    	je     1c80 <l2cap_parse_conf_req+0x270>
    1a97:	0f 86 b3 01 00 00    	jbe    1c50 <l2cap_parse_conf_req+0x240>
    1a9d:	3c 04                	cmp    $0x4,%al
    1a9f:	0f 84 cb 01 00 00    	je     1c70 <l2cap_parse_conf_req+0x260>
    1aa5:	3c 05                	cmp    $0x5,%al
    1aa7:	0f 85 b3 01 00 00    	jne    1c60 <l2cap_parse_conf_req+0x250>
static inline u32 get_unaligned_le32(const void *p)
{
	return le32_to_cpup((__le32 *)p);
}

static inline u64 get_unaligned_le64(const void *p)
    1aad:	4d 8b 49 02          	mov    0x2(%r9),%r9
	BT_DBG("type 0x%2.2x len %d val 0x%lx", *type, opt->len, *val);
    1ab1:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 1ab8 <l2cap_parse_conf_req+0xa8>
    1ab8:	0f 85 fd 04 00 00    	jne    1fbb <l2cap_parse_conf_req+0x5ab>
		type &= L2CAP_CONF_MASK;
    1abe:	44 89 f0             	mov    %r14d,%eax
		len -= l2cap_get_conf_opt(&req, &type, &olen, &val);
    1ac1:	44 29 e3             	sub    %r12d,%ebx
		type &= L2CAP_CONF_MASK;
    1ac4:	83 e0 7f             	and    $0x7f,%eax
		switch (type) {
    1ac7:	3c 07                	cmp    $0x7,%al
    1ac9:	77 0d                	ja     1ad8 <l2cap_parse_conf_req+0xc8>
    1acb:	0f b6 d0             	movzbl %al,%edx
    1ace:	ff 24 d5 00 00 00 00 	jmpq   *0x0(,%rdx,8)
    1ad5:	0f 1f 00             	nopl   (%rax)
			if (hint)
    1ad8:	45 84 f6             	test   %r14b,%r14b
    1adb:	78 23                	js     1b00 <l2cap_parse_conf_req+0xf0>
			*((u8 *) ptr++) = type;
    1add:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
			result = L2CAP_CONF_UNKNOWN;
    1ae1:	41 bc 03 00 00 00    	mov    $0x3,%r12d
    1ae7:	66 44 89 65 98       	mov    %r12w,-0x68(%rbp)
			*((u8 *) ptr++) = type;
    1aec:	48 8d 4a 01          	lea    0x1(%rdx),%rcx
    1af0:	48 89 4d a8          	mov    %rcx,-0x58(%rbp)
    1af4:	88 02                	mov    %al,(%rdx)
    1af6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    1afd:	00 00 00 
	while (len >= L2CAP_CONF_OPT_SIZE) {
    1b00:	83 fb 01             	cmp    $0x1,%ebx
    1b03:	7e 1b                	jle    1b20 <l2cap_parse_conf_req+0x110>
    1b05:	4d 89 f9             	mov    %r15,%r9
    1b08:	e9 6b ff ff ff       	jmpq   1a78 <l2cap_parse_conf_req+0x68>
    1b0d:	0f 1f 00             	nopl   (%rax)
    1b10:	83 fb 01             	cmp    $0x1,%ebx
			chan->flush_to = val;
    1b13:	66 45 89 4a 22       	mov    %r9w,0x22(%r10)
	while (len >= L2CAP_CONF_OPT_SIZE) {
    1b18:	7f eb                	jg     1b05 <l2cap_parse_conf_req+0xf5>
    1b1a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
	if (chan->num_conf_rsp || chan->num_conf_req > 1)
    1b20:	41 0f b6 42 6e       	movzbl 0x6e(%r10),%eax
    1b25:	84 c0                	test   %al,%al
    1b27:	0f 84 63 01 00 00    	je     1c90 <l2cap_parse_conf_req+0x280>
    1b2d:	0f b6 4d b7          	movzbl -0x49(%rbp),%ecx
    1b31:	41 0f b6 52 24       	movzbl 0x24(%r10),%edx
	if (chan->mode != rfc.mode) {
    1b36:	38 ca                	cmp    %cl,%dl
    1b38:	0f 84 c2 01 00 00    	je     1d00 <l2cap_parse_conf_req+0x2f0>
		if (chan->num_conf_rsp == 1)
    1b3e:	3c 01                	cmp    $0x1,%al
    1b40:	4c 89 55 90          	mov    %r10,-0x70(%rbp)
		rfc.mode = chan->mode;
    1b44:	88 55 b7             	mov    %dl,-0x49(%rbp)
		if (chan->num_conf_rsp == 1)
    1b47:	0f 84 c5 03 00 00    	je     1f12 <l2cap_parse_conf_req+0x502>
		l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC,
    1b4d:	48 8d 4d b7          	lea    -0x49(%rbp),%rcx
    1b51:	48 8d 7d a8          	lea    -0x58(%rbp),%rdi
    1b55:	ba 09 00 00 00       	mov    $0x9,%edx
    1b5a:	be 04 00 00 00       	mov    $0x4,%esi
    1b5f:	e8 4c ea ff ff       	callq  5b0 <l2cap_add_conf_opt>
		result = L2CAP_CONF_UNACCEPT;
    1b64:	41 ba 01 00 00 00    	mov    $0x1,%r10d
    1b6a:	66 44 89 55 98       	mov    %r10w,-0x68(%rbp)
    1b6f:	4c 8b 55 90          	mov    -0x70(%rbp),%r10
	rsp->scid   = cpu_to_le16(chan->dcid);
    1b73:	41 0f b7 42 1a       	movzwl 0x1a(%r10),%eax
    1b78:	48 8b 7d 88          	mov    -0x78(%rbp),%rdi
    1b7c:	66 89 07             	mov    %ax,(%rdi)
	rsp->result = cpu_to_le16(result);
    1b7f:	0f b7 45 98          	movzwl -0x68(%rbp),%eax
    1b83:	66 89 47 04          	mov    %ax,0x4(%rdi)
	rsp->flags  = cpu_to_le16(0x0000);
    1b87:	31 c0                	xor    %eax,%eax
    1b89:	66 89 47 02          	mov    %ax,0x2(%rdi)
	return ptr - data;
    1b8d:	8b 45 a8             	mov    -0x58(%rbp),%eax
}
    1b90:	48 83 c4 68          	add    $0x68,%rsp
    1b94:	5b                   	pop    %rbx
    1b95:	41 5c                	pop    %r12
    1b97:	41 5d                	pop    %r13
    1b99:	41 5e                	pop    %r14
    1b9b:	41 5f                	pop    %r15
	return ptr - data;
    1b9d:	29 f8                	sub    %edi,%eax
}
    1b9f:	5d                   	pop    %rbp
    1ba0:	c3                   	retq   
    1ba1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
			mtu = val;
    1ba8:	45 89 cb             	mov    %r9d,%r11d
			break;
    1bab:	e9 50 ff ff ff       	jmpq   1b00 <l2cap_parse_conf_req+0xf0>
			if (!enable_hs)
    1bb0:	80 3d 00 00 00 00 00 	cmpb   $0x0,0x0(%rip)        # 1bb7 <l2cap_parse_conf_req+0x1a7>
    1bb7:	0f 84 55 03 00 00    	je     1f12 <l2cap_parse_conf_req+0x502>
    1bbd:	f0 41 80 8a 90 00 00 	lock orb $0x10,0x90(%r10)
    1bc4:	00 10 
    1bc6:	f0 41 80 8a 81 00 00 	lock orb $0x1,0x81(%r10)
    1bcd:	00 01 
			chan->tx_win_max = L2CAP_DEFAULT_EXT_WINDOW;
    1bcf:	41 bd ff 3f 00 00    	mov    $0x3fff,%r13d
			chan->remote_tx_win = val;
    1bd5:	66 45 89 8a c8 00 00 	mov    %r9w,0xc8(%r10)
    1bdc:	00 
			chan->tx_win_max = L2CAP_DEFAULT_EXT_WINDOW;
    1bdd:	66 45 89 6a 72       	mov    %r13w,0x72(%r10)
			break;
    1be2:	e9 19 ff ff ff       	jmpq   1b00 <l2cap_parse_conf_req+0xf0>
    1be7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    1bee:	00 00 
			if (olen == sizeof(efs))
    1bf0:	41 83 fd 10          	cmp    $0x10,%r13d
			remote_efs = 1;
    1bf4:	c6 45 90 01          	movb   $0x1,-0x70(%rbp)
			if (olen == sizeof(efs))
    1bf8:	0f 85 02 ff ff ff    	jne    1b00 <l2cap_parse_conf_req+0xf0>
				memcpy(&efs, (void *) val, olen);
    1bfe:	49 8b 01             	mov    (%r9),%rax
    1c01:	49 8b 51 08          	mov    0x8(%r9),%rdx
    1c05:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    1c09:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    1c0d:	e9 ee fe ff ff       	jmpq   1b00 <l2cap_parse_conf_req+0xf0>
    1c12:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
			if (val == L2CAP_FCS_NONE)
    1c18:	4d 85 c9             	test   %r9,%r9
    1c1b:	0f 85 df fe ff ff    	jne    1b00 <l2cap_parse_conf_req+0xf0>
    1c21:	f0 41 80 8a 80 00 00 	lock orb $0x40,0x80(%r10)
    1c28:	00 40 
    1c2a:	e9 d1 fe ff ff       	jmpq   1b00 <l2cap_parse_conf_req+0xf0>
    1c2f:	90                   	nop
			if (olen == sizeof(rfc))
    1c30:	41 83 fd 09          	cmp    $0x9,%r13d
    1c34:	0f 85 c6 fe ff ff    	jne    1b00 <l2cap_parse_conf_req+0xf0>
				memcpy(&rfc, (void *) val, olen);
    1c3a:	49 8b 01             	mov    (%r9),%rax
    1c3d:	48 89 45 b7          	mov    %rax,-0x49(%rbp)
    1c41:	41 0f b6 41 08       	movzbl 0x8(%r9),%eax
    1c46:	88 45 bf             	mov    %al,-0x41(%rbp)
    1c49:	e9 b2 fe ff ff       	jmpq   1b00 <l2cap_parse_conf_req+0xf0>
    1c4e:	66 90                	xchg   %ax,%ax
	switch (opt->len) {
    1c50:	3c 01                	cmp    $0x1,%al
    1c52:	75 0c                	jne    1c60 <l2cap_parse_conf_req+0x250>
		*val = *((u8 *) opt->val);
    1c54:	45 0f b6 49 02       	movzbl 0x2(%r9),%r9d
    1c59:	e9 53 fe ff ff       	jmpq   1ab1 <l2cap_parse_conf_req+0xa1>
    1c5e:	66 90                	xchg   %ax,%ax
		*val = (unsigned long) opt->val;
    1c60:	49 83 c1 02          	add    $0x2,%r9
    1c64:	e9 48 fe ff ff       	jmpq   1ab1 <l2cap_parse_conf_req+0xa1>
    1c69:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		*val = get_unaligned_le32(opt->val);
    1c70:	45 8b 49 02          	mov    0x2(%r9),%r9d
    1c74:	e9 38 fe ff ff       	jmpq   1ab1 <l2cap_parse_conf_req+0xa1>
    1c79:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		*val = get_unaligned_le16(opt->val);
    1c80:	45 0f b7 49 02       	movzwl 0x2(%r9),%r9d
    1c85:	e9 27 fe ff ff       	jmpq   1ab1 <l2cap_parse_conf_req+0xa1>
    1c8a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
	if (chan->num_conf_rsp || chan->num_conf_req > 1)
    1c90:	41 80 7a 6d 01       	cmpb   $0x1,0x6d(%r10)
    1c95:	0f 87 92 fe ff ff    	ja     1b2d <l2cap_parse_conf_req+0x11d>
	switch (chan->mode) {
    1c9b:	41 0f b6 52 24       	movzbl 0x24(%r10),%edx
    1ca0:	8d 4a fd             	lea    -0x3(%rdx),%ecx
    1ca3:	80 f9 01             	cmp    $0x1,%cl
    1ca6:	76 09                	jbe    1cb1 <l2cap_parse_conf_req+0x2a1>
    1ca8:	0f b6 4d b7          	movzbl -0x49(%rbp),%ecx
    1cac:	e9 85 fe ff ff       	jmpq   1b36 <l2cap_parse_conf_req+0x126>
		(addr[nr / BITS_PER_LONG])) != 0;
    1cb1:	49 8b 8a 80 00 00 00 	mov    0x80(%r10),%rcx
		if (!test_bit(CONF_STATE2_DEVICE, &chan->conf_state)) {
    1cb8:	81 e1 80 00 00 00    	and    $0x80,%ecx
    1cbe:	0f 84 b5 02 00 00    	je     1f79 <l2cap_parse_conf_req+0x569>
		if (remote_efs) {
    1cc4:	80 7d 90 00          	cmpb   $0x0,-0x70(%rbp)
    1cc8:	74 29                	je     1cf3 <l2cap_parse_conf_req+0x2e3>
	return enable_hs && chan->conn->feat_mask & L2CAP_FEAT_EXT_FLOW;
    1cca:	80 3d 00 00 00 00 00 	cmpb   $0x0,0x0(%rip)        # 1cd1 <l2cap_parse_conf_req+0x2c1>
    1cd1:	0f 84 3b 02 00 00    	je     1f12 <l2cap_parse_conf_req+0x502>
    1cd7:	49 8b 42 08          	mov    0x8(%r10),%rax
    1cdb:	f6 40 24 40          	testb  $0x40,0x24(%rax)
    1cdf:	0f 84 2d 02 00 00    	je     1f12 <l2cap_parse_conf_req+0x502>
		asm volatile(LOCK_PREFIX "orb %1,%0"
    1ce5:	f0 41 80 8a 90 00 00 	lock orb $0x20,0x90(%r10)
    1cec:	00 20 
    1cee:	41 0f b6 52 24       	movzbl 0x24(%r10),%edx
		if (chan->mode != rfc.mode)
    1cf3:	38 55 b7             	cmp    %dl,-0x49(%rbp)
    1cf6:	0f 85 16 02 00 00    	jne    1f12 <l2cap_parse_conf_req+0x502>
    1cfc:	0f 1f 40 00          	nopl   0x0(%rax)
	if (result == L2CAP_CONF_SUCCESS) {
    1d00:	66 83 7d 98 00       	cmpw   $0x0,-0x68(%rbp)
    1d05:	0f 85 68 fe ff ff    	jne    1b73 <l2cap_parse_conf_req+0x163>
		if (mtu < L2CAP_DEFAULT_MIN_MTU)
    1d0b:	66 41 83 fb 2f       	cmp    $0x2f,%r11w
    1d10:	0f 86 c2 00 00 00    	jbe    1dd8 <l2cap_parse_conf_req+0x3c8>
			chan->omtu = mtu;
    1d16:	66 45 89 5a 20       	mov    %r11w,0x20(%r10)
    1d1b:	f0 41 80 8a 80 00 00 	lock orb $0x8,0x80(%r10)
    1d22:	00 08 
		l2cap_add_conf_opt(&ptr, L2CAP_CONF_MTU, 2, chan->omtu);
    1d24:	41 0f b7 4a 20       	movzwl 0x20(%r10),%ecx
    1d29:	48 8d 7d a8          	lea    -0x58(%rbp),%rdi
    1d2d:	ba 02 00 00 00       	mov    $0x2,%edx
    1d32:	be 01 00 00 00       	mov    $0x1,%esi
    1d37:	4c 89 55 80          	mov    %r10,-0x80(%rbp)
    1d3b:	e8 70 e8 ff ff       	callq  5b0 <l2cap_add_conf_opt>
		if (remote_efs) {
    1d40:	80 7d 90 00          	cmpb   $0x0,-0x70(%rbp)
    1d44:	4c 8b 55 80          	mov    -0x80(%rbp),%r10
    1d48:	74 56                	je     1da0 <l2cap_parse_conf_req+0x390>
			if (chan->local_stype != L2CAP_SERV_NOTRAFIC &&
    1d4a:	41 0f b6 82 cf 00 00 	movzbl 0xcf(%r10),%eax
    1d51:	00 
    1d52:	84 c0                	test   %al,%al
    1d54:	0f 84 8e 00 00 00    	je     1de8 <l2cap_parse_conf_req+0x3d8>
					efs.stype != L2CAP_SERV_NOTRAFIC &&
    1d5a:	0f b6 55 c1          	movzbl -0x3f(%rbp),%edx
			if (chan->local_stype != L2CAP_SERV_NOTRAFIC &&
    1d5e:	84 d2                	test   %dl,%dl
    1d60:	0f 84 82 00 00 00    	je     1de8 <l2cap_parse_conf_req+0x3d8>
					efs.stype != L2CAP_SERV_NOTRAFIC &&
    1d66:	38 d0                	cmp    %dl,%al
    1d68:	74 7e                	je     1de8 <l2cap_parse_conf_req+0x3d8>
				if (chan->num_conf_req >= 1)
    1d6a:	41 80 7a 6d 00       	cmpb   $0x0,0x6d(%r10)
    1d6f:	4c 89 55 90          	mov    %r10,-0x70(%rbp)
    1d73:	0f 85 99 01 00 00    	jne    1f12 <l2cap_parse_conf_req+0x502>
				l2cap_add_conf_opt(&ptr, L2CAP_CONF_EFS,
    1d79:	48 8d 4d c0          	lea    -0x40(%rbp),%rcx
    1d7d:	48 8d 7d a8          	lea    -0x58(%rbp),%rdi
    1d81:	ba 10 00 00 00       	mov    $0x10,%edx
    1d86:	be 06 00 00 00       	mov    $0x6,%esi
    1d8b:	e8 20 e8 ff ff       	callq  5b0 <l2cap_add_conf_opt>
    1d90:	4c 8b 55 90          	mov    -0x70(%rbp),%r10
				result = L2CAP_CONF_UNACCEPT;
    1d94:	41 b8 01 00 00 00    	mov    $0x1,%r8d
    1d9a:	66 44 89 45 98       	mov    %r8w,-0x68(%rbp)
    1d9f:	90                   	nop
		switch (rfc.mode) {
    1da0:	0f b6 45 b7          	movzbl -0x49(%rbp),%eax
    1da4:	3c 03                	cmp    $0x3,%al
    1da6:	74 5a                	je     1e02 <l2cap_parse_conf_req+0x3f2>
    1da8:	3c 04                	cmp    $0x4,%al
    1daa:	0f 84 76 01 00 00    	je     1f26 <l2cap_parse_conf_req+0x516>
    1db0:	84 c0                	test   %al,%al
    1db2:	0f 84 33 01 00 00    	je     1eeb <l2cap_parse_conf_req+0x4db>
			result = L2CAP_CONF_UNACCEPT;
    1db8:	ba 01 00 00 00       	mov    $0x1,%edx
			memset(&rfc, 0, sizeof(rfc));
    1dbd:	48 c7 45 b7 00 00 00 	movq   $0x0,-0x49(%rbp)
    1dc4:	00 
    1dc5:	c6 45 bf 00          	movb   $0x0,-0x41(%rbp)
			result = L2CAP_CONF_UNACCEPT;
    1dc9:	66 89 55 98          	mov    %dx,-0x68(%rbp)
    1dcd:	e9 a1 fd ff ff       	jmpq   1b73 <l2cap_parse_conf_req+0x163>
    1dd2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
			result = L2CAP_CONF_UNACCEPT;
    1dd8:	41 b9 01 00 00 00    	mov    $0x1,%r9d
    1dde:	66 44 89 4d 98       	mov    %r9w,-0x68(%rbp)
    1de3:	e9 3c ff ff ff       	jmpq   1d24 <l2cap_parse_conf_req+0x314>
    1de8:	f0 41 80 8a 81 00 00 	lock orb $0x2,0x81(%r10)
    1def:	00 02 
		switch (rfc.mode) {
    1df1:	0f b6 45 b7          	movzbl -0x49(%rbp),%eax
				result = L2CAP_CONF_PENDING;
    1df5:	bf 04 00 00 00       	mov    $0x4,%edi
    1dfa:	66 89 7d 98          	mov    %di,-0x68(%rbp)
		switch (rfc.mode) {
    1dfe:	3c 03                	cmp    $0x3,%al
    1e00:	75 a6                	jne    1da8 <l2cap_parse_conf_req+0x398>
		(addr[nr / BITS_PER_LONG])) != 0;
    1e02:	49 8b 82 80 00 00 00 	mov    0x80(%r10),%rax
			if (!test_bit(CONF_EWS_RECV, &chan->conf_state))
    1e09:	f6 c4 01             	test   $0x1,%ah
    1e0c:	0f 85 5e 01 00 00    	jne    1f70 <l2cap_parse_conf_req+0x560>
				chan->remote_tx_win = rfc.txwin_size;
    1e12:	0f b6 45 b8          	movzbl -0x48(%rbp),%eax
    1e16:	66 41 89 82 c8 00 00 	mov    %ax,0xc8(%r10)
    1e1d:	00 
			chan->remote_max_tx = rfc.max_transmit;
    1e1e:	0f b6 45 b9          	movzbl -0x47(%rbp),%eax
			rfc.retrans_timeout =
    1e22:	b9 d0 07 00 00       	mov    $0x7d0,%ecx
			rfc.monitor_timeout =
    1e27:	be e0 2e 00 00       	mov    $0x2ee0,%esi
			rfc.retrans_timeout =
    1e2c:	66 89 4d ba          	mov    %cx,-0x46(%rbp)
			rfc.monitor_timeout =
    1e30:	66 89 75 bc          	mov    %si,-0x44(%rbp)
			chan->remote_max_tx = rfc.max_transmit;
    1e34:	41 88 82 ca 00 00 00 	mov    %al,0xca(%r10)
			size = min_t(u16, le16_to_cpu(rfc.max_pdu_size),
    1e3b:	49 8b 42 08          	mov    0x8(%r10),%rax
    1e3f:	8b 50 20             	mov    0x20(%rax),%edx
    1e42:	0f b7 45 be          	movzwl -0x42(%rbp),%eax
    1e46:	83 ea 0c             	sub    $0xc,%edx
    1e49:	66 39 c2             	cmp    %ax,%dx
    1e4c:	0f 46 c2             	cmovbe %edx,%eax
			rfc.max_pdu_size = cpu_to_le16(size);
    1e4f:	66 89 45 be          	mov    %ax,-0x42(%rbp)
			chan->remote_mps = size;
    1e53:	66 41 89 82 cc 00 00 	mov    %ax,0xcc(%r10)
    1e5a:	00 
		asm volatile(LOCK_PREFIX "orb %1,%0"
    1e5b:	f0 41 80 8a 80 00 00 	lock orb $0x10,0x80(%r10)
    1e62:	00 10 
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC,
    1e64:	48 8d 4d b7          	lea    -0x49(%rbp),%rcx
    1e68:	48 8d 7d a8          	lea    -0x58(%rbp),%rdi
    1e6c:	ba 09 00 00 00       	mov    $0x9,%edx
    1e71:	be 04 00 00 00       	mov    $0x4,%esi
    1e76:	4c 89 55 90          	mov    %r10,-0x70(%rbp)
    1e7a:	e8 31 e7 ff ff       	callq  5b0 <l2cap_add_conf_opt>
		(addr[nr / BITS_PER_LONG])) != 0;
    1e7f:	4c 8b 55 90          	mov    -0x70(%rbp),%r10
    1e83:	49 8b 82 90 00 00 00 	mov    0x90(%r10),%rax
			if (test_bit(FLAG_EFS_ENABLE, &chan->flags)) {
    1e8a:	a8 20                	test   $0x20,%al
    1e8c:	74 6b                	je     1ef9 <l2cap_parse_conf_req+0x4e9>
				chan->remote_id = efs.id;
    1e8e:	0f b6 45 c0          	movzbl -0x40(%rbp),%eax
				l2cap_add_conf_opt(&ptr, L2CAP_CONF_EFS,
    1e92:	48 8d 4d c0          	lea    -0x40(%rbp),%rcx
    1e96:	48 8d 7d a8          	lea    -0x58(%rbp),%rdi
    1e9a:	ba 10 00 00 00       	mov    $0x10,%edx
    1e9f:	be 06 00 00 00       	mov    $0x6,%esi
				chan->remote_id = efs.id;
    1ea4:	41 88 82 e0 00 00 00 	mov    %al,0xe0(%r10)
				chan->remote_stype = efs.stype;
    1eab:	0f b6 45 c1          	movzbl -0x3f(%rbp),%eax
    1eaf:	41 88 82 e1 00 00 00 	mov    %al,0xe1(%r10)
				chan->remote_msdu = le16_to_cpu(efs.msdu);
    1eb6:	0f b7 45 c2          	movzwl -0x3e(%rbp),%eax
    1eba:	66 41 89 82 e2 00 00 	mov    %ax,0xe2(%r10)
    1ec1:	00 
				chan->remote_flush_to =
    1ec2:	8b 45 cc             	mov    -0x34(%rbp),%eax
    1ec5:	41 89 82 ec 00 00 00 	mov    %eax,0xec(%r10)
				chan->remote_acc_lat =
    1ecc:	8b 45 c8             	mov    -0x38(%rbp),%eax
    1ecf:	41 89 82 e8 00 00 00 	mov    %eax,0xe8(%r10)
				chan->remote_sdu_itime =
    1ed6:	8b 45 c4             	mov    -0x3c(%rbp),%eax
    1ed9:	41 89 82 e4 00 00 00 	mov    %eax,0xe4(%r10)
				l2cap_add_conf_opt(&ptr, L2CAP_CONF_EFS,
    1ee0:	e8 cb e6 ff ff       	callq  5b0 <l2cap_add_conf_opt>
    1ee5:	4c 8b 55 90          	mov    -0x70(%rbp),%r10
    1ee9:	eb 0e                	jmp    1ef9 <l2cap_parse_conf_req+0x4e9>
			chan->fcs = L2CAP_FCS_NONE;
    1eeb:	41 c6 42 6f 00       	movb   $0x0,0x6f(%r10)
		asm volatile(LOCK_PREFIX "orb %1,%0"
    1ef0:	f0 41 80 8a 80 00 00 	lock orb $0x10,0x80(%r10)
    1ef7:	00 10 
		if (result == L2CAP_CONF_SUCCESS)
    1ef9:	66 83 7d 98 00       	cmpw   $0x0,-0x68(%rbp)
    1efe:	0f 85 6f fc ff ff    	jne    1b73 <l2cap_parse_conf_req+0x163>
    1f04:	f0 41 80 8a 80 00 00 	lock orb $0x4,0x80(%r10)
    1f0b:	00 04 
    1f0d:	e9 61 fc ff ff       	jmpq   1b73 <l2cap_parse_conf_req+0x163>
}
    1f12:	48 83 c4 68          	add    $0x68,%rsp
				return -ECONNREFUSED;
    1f16:	b8 91 ff ff ff       	mov    $0xffffff91,%eax
}
    1f1b:	5b                   	pop    %rbx
    1f1c:	41 5c                	pop    %r12
    1f1e:	41 5d                	pop    %r13
    1f20:	41 5e                	pop    %r14
    1f22:	41 5f                	pop    %r15
    1f24:	5d                   	pop    %rbp
    1f25:	c3                   	retq   
			size = min_t(u16, le16_to_cpu(rfc.max_pdu_size),
    1f26:	49 8b 42 08          	mov    0x8(%r10),%rax
    1f2a:	8b 50 20             	mov    0x20(%rax),%edx
    1f2d:	0f b7 45 be          	movzwl -0x42(%rbp),%eax
    1f31:	83 ea 0c             	sub    $0xc,%edx
    1f34:	66 39 c2             	cmp    %ax,%dx
    1f37:	0f 46 c2             	cmovbe %edx,%eax
			rfc.max_pdu_size = cpu_to_le16(size);
    1f3a:	66 89 45 be          	mov    %ax,-0x42(%rbp)
			chan->remote_mps = size;
    1f3e:	66 41 89 82 cc 00 00 	mov    %ax,0xcc(%r10)
    1f45:	00 
    1f46:	f0 41 80 8a 80 00 00 	lock orb $0x10,0x80(%r10)
    1f4d:	00 10 
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC,
    1f4f:	48 8d 4d b7          	lea    -0x49(%rbp),%rcx
    1f53:	48 8d 7d a8          	lea    -0x58(%rbp),%rdi
    1f57:	ba 09 00 00 00       	mov    $0x9,%edx
    1f5c:	be 04 00 00 00       	mov    $0x4,%esi
    1f61:	4c 89 55 90          	mov    %r10,-0x70(%rbp)
    1f65:	e8 46 e6 ff ff       	callq  5b0 <l2cap_add_conf_opt>
			break;
    1f6a:	4c 8b 55 90          	mov    -0x70(%rbp),%r10
    1f6e:	eb 89                	jmp    1ef9 <l2cap_parse_conf_req+0x4e9>
				rfc.txwin_size = L2CAP_DEFAULT_TX_WINDOW;
    1f70:	c6 45 b8 3f          	movb   $0x3f,-0x48(%rbp)
    1f74:	e9 a5 fe ff ff       	jmpq   1e1e <l2cap_parse_conf_req+0x40e>
			chan->mode = l2cap_select_mode(rfc.mode,
    1f79:	0f b6 4d b7          	movzbl -0x49(%rbp),%ecx
					chan->conn->feat_mask);
    1f7d:	49 8b 52 08          	mov    0x8(%r10),%rdx
    1f81:	8b 72 24             	mov    0x24(%rdx),%esi
		return L2CAP_MODE_BASIC;
    1f84:	31 d2                	xor    %edx,%edx
	switch (mode) {
    1f86:	8d 79 fd             	lea    -0x3(%rcx),%edi
    1f89:	40 80 ff 01          	cmp    $0x1,%dil
    1f8d:	77 23                	ja     1fb2 <l2cap_parse_conf_req+0x5a2>
	u32 local_feat_mask = l2cap_feat_mask;
    1f8f:	80 3d 00 00 00 00 01 	cmpb   $0x1,0x0(%rip)        # 1f96 <l2cap_parse_conf_req+0x586>
    1f96:	0f b7 f6             	movzwl %si,%esi
    1f99:	19 d2                	sbb    %edx,%edx
    1f9b:	83 e2 18             	and    $0x18,%edx
    1f9e:	83 ea 80             	sub    $0xffffff80,%edx
		return L2CAP_FEAT_STREAMING & feat_mask & local_feat_mask;
    1fa1:	21 d6                	and    %edx,%esi
	switch (mode) {
    1fa3:	80 f9 04             	cmp    $0x4,%cl
    1fa6:	75 5b                	jne    2003 <l2cap_parse_conf_req+0x5f3>
		return L2CAP_FEAT_STREAMING & feat_mask & local_feat_mask;
    1fa8:	83 e6 10             	and    $0x10,%esi
		return L2CAP_MODE_BASIC;
    1fab:	31 d2                	xor    %edx,%edx
    1fad:	85 f6                	test   %esi,%esi
    1faf:	0f 45 d1             	cmovne %ecx,%edx
			chan->mode = l2cap_select_mode(rfc.mode,
    1fb2:	41 88 52 24          	mov    %dl,0x24(%r10)
			break;
    1fb6:	e9 7b fb ff ff       	jmpq   1b36 <l2cap_parse_conf_req+0x126>
	BT_DBG("type 0x%2.2x len %d val 0x%lx", *type, opt->len, *val);
    1fbb:	4d 89 c8             	mov    %r9,%r8
	*type = opt->type;
    1fbe:	41 0f b6 d6          	movzbl %r14b,%edx
	BT_DBG("type 0x%2.2x len %d val 0x%lx", *type, opt->len, *val);
    1fc2:	44 89 e9             	mov    %r13d,%ecx
    1fc5:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    1fcc:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    1fd3:	31 c0                	xor    %eax,%eax
    1fd5:	4c 89 95 70 ff ff ff 	mov    %r10,-0x90(%rbp)
    1fdc:	44 89 9d 7c ff ff ff 	mov    %r11d,-0x84(%rbp)
    1fe3:	4c 89 4d 80          	mov    %r9,-0x80(%rbp)
    1fe7:	e8 00 00 00 00       	callq  1fec <l2cap_parse_conf_req+0x5dc>
    1fec:	4c 8b 95 70 ff ff ff 	mov    -0x90(%rbp),%r10
    1ff3:	44 8b 9d 7c ff ff ff 	mov    -0x84(%rbp),%r11d
    1ffa:	4c 8b 4d 80          	mov    -0x80(%rbp),%r9
    1ffe:	e9 bb fa ff ff       	jmpq   1abe <l2cap_parse_conf_req+0xae>
		return L2CAP_FEAT_ERTM & feat_mask & local_feat_mask;
    2003:	83 e6 08             	and    $0x8,%esi
    2006:	eb a3                	jmp    1fab <l2cap_parse_conf_req+0x59b>
	BT_DBG("chan %p", chan);
    2008:	48 89 fa             	mov    %rdi,%rdx
    200b:	48 89 7d 98          	mov    %rdi,-0x68(%rbp)
    200f:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    2016:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    201d:	31 c0                	xor    %eax,%eax
    201f:	4c 89 4d 90          	mov    %r9,-0x70(%rbp)
    2023:	e8 00 00 00 00       	callq  2028 <l2cap_parse_conf_req+0x618>
    2028:	4c 8b 4d 90          	mov    -0x70(%rbp),%r9
    202c:	4c 8b 55 98          	mov    -0x68(%rbp),%r10
    2030:	e9 24 fa ff ff       	jmpq   1a59 <l2cap_parse_conf_req+0x49>
    2035:	90                   	nop
    2036:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    203d:	00 00 00 

0000000000002040 <l2cap_parse_conf_rsp>:
{
    2040:	55                   	push   %rbp
    2041:	48 89 e5             	mov    %rsp,%rbp
    2044:	41 57                	push   %r15
    2046:	41 56                	push   %r14
    2048:	41 55                	push   %r13
    204a:	41 54                	push   %r12
    204c:	53                   	push   %rbx
    204d:	48 83 ec 58          	sub    $0x58,%rsp
    2051:	e8 00 00 00 00       	callq  2056 <l2cap_parse_conf_rsp+0x16>
    2056:	48 89 c8             	mov    %rcx,%rax
    2059:	49 89 fe             	mov    %rdi,%r14
    205c:	48 89 f3             	mov    %rsi,%rbx
	void *ptr = req->data;
    205f:	48 83 c0 04          	add    $0x4,%rax
	BT_DBG("chan %p, rsp %p, len %d, req %p", chan, rsp, len, data);
    2063:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 206a <l2cap_parse_conf_rsp+0x2a>
{
    206a:	41 89 d4             	mov    %edx,%r12d
    206d:	48 89 4d 90          	mov    %rcx,-0x70(%rbp)
    2071:	4c 89 45 98          	mov    %r8,-0x68(%rbp)
	void *ptr = req->data;
    2075:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
	struct l2cap_conf_rfc rfc = { .mode = L2CAP_MODE_BASIC };
    2079:	48 c7 45 b7 00 00 00 	movq   $0x0,-0x49(%rbp)
    2080:	00 
    2081:	c6 45 bf 00          	movb   $0x0,-0x41(%rbp)
	BT_DBG("chan %p, rsp %p, len %d, req %p", chan, rsp, len, data);
    2085:	0f 85 4a 03 00 00    	jne    23d5 <l2cap_parse_conf_rsp+0x395>
	while (len >= L2CAP_CONF_OPT_SIZE) {
    208b:	41 83 fc 01          	cmp    $0x1,%r12d
			chan->tx_win = min_t(u16, val,
    208f:	41 bf ff 3f 00 00    	mov    $0x3fff,%r15d
	while (len >= L2CAP_CONF_OPT_SIZE) {
    2095:	0f 8e 9f 00 00 00    	jle    213a <l2cap_parse_conf_rsp+0xfa>
    209b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
	len = L2CAP_CONF_OPT_SIZE + opt->len;
    20a0:	0f b6 43 01          	movzbl 0x1(%rbx),%eax
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC,
    20a4:	49 89 db             	mov    %rbx,%r11
	*type = opt->type;
    20a7:	45 0f b6 0b          	movzbl (%r11),%r9d
	len = L2CAP_CONF_OPT_SIZE + opt->len;
    20ab:	44 0f b6 d0          	movzbl %al,%r10d
    20af:	45 8d 6a 02          	lea    0x2(%r10),%r13d
	*ptr += len;
    20b3:	49 63 dd             	movslq %r13d,%rbx
    20b6:	4c 01 db             	add    %r11,%rbx
	switch (opt->len) {
    20b9:	3c 02                	cmp    $0x2,%al
    20bb:	0f 84 ff 01 00 00    	je     22c0 <l2cap_parse_conf_rsp+0x280>
    20c1:	0f 86 e1 01 00 00    	jbe    22a8 <l2cap_parse_conf_rsp+0x268>
    20c7:	3c 04                	cmp    $0x4,%al
    20c9:	0f 84 01 02 00 00    	je     22d0 <l2cap_parse_conf_rsp+0x290>
    20cf:	3c 05                	cmp    $0x5,%al
    20d1:	0f 85 09 02 00 00    	jne    22e0 <l2cap_parse_conf_rsp+0x2a0>
    20d7:	4d 8b 5b 02          	mov    0x2(%r11),%r11
	BT_DBG("type 0x%2.2x len %d val 0x%lx", *type, opt->len, *val);
    20db:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 20e2 <l2cap_parse_conf_rsp+0xa2>
    20e2:	0f 85 b1 02 00 00    	jne    2399 <l2cap_parse_conf_rsp+0x359>
		len -= l2cap_get_conf_opt(&rsp, &type, &olen, &val);
    20e8:	45 29 ec             	sub    %r13d,%r12d
		switch (type) {
    20eb:	41 80 f9 07          	cmp    $0x7,%r9b
    20ef:	77 3f                	ja     2130 <l2cap_parse_conf_rsp+0xf0>
    20f1:	45 0f b6 c9          	movzbl %r9b,%r9d
    20f5:	42 ff 24 cd 00 00 00 	jmpq   *0x0(,%r9,8)
    20fc:	00 
    20fd:	0f 1f 00             	nopl   (%rax)
			chan->tx_win = min_t(u16, val,
    2100:	66 41 81 fb ff 3f    	cmp    $0x3fff,%r11w
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_EWS, 2,
    2106:	48 8d 7d a8          	lea    -0x58(%rbp),%rdi
    210a:	ba 02 00 00 00       	mov    $0x2,%edx
			chan->tx_win = min_t(u16, val,
    210f:	45 0f 47 df          	cmova  %r15d,%r11d
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_EWS, 2,
    2113:	be 07 00 00 00       	mov    $0x7,%esi
			chan->tx_win = min_t(u16, val,
    2118:	66 45 89 5e 70       	mov    %r11w,0x70(%r14)
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_EWS, 2,
    211d:	41 0f b7 cb          	movzwl %r11w,%ecx
    2121:	e8 8a e4 ff ff       	callq  5b0 <l2cap_add_conf_opt>
    2126:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    212d:	00 00 00 
	while (len >= L2CAP_CONF_OPT_SIZE) {
    2130:	41 83 fc 01          	cmp    $0x1,%r12d
    2134:	0f 8f 66 ff ff ff    	jg     20a0 <l2cap_parse_conf_rsp+0x60>
	if (chan->mode == L2CAP_MODE_BASIC && chan->mode != rfc.mode)
    213a:	41 80 7e 24 00       	cmpb   $0x0,0x24(%r14)
    213f:	0f 85 2b 01 00 00    	jne    2270 <l2cap_parse_conf_rsp+0x230>
    2145:	80 7d b7 00          	cmpb   $0x0,-0x49(%rbp)
    2149:	0f 85 dd 01 00 00    	jne    232c <l2cap_parse_conf_rsp+0x2ec>
	req->dcid   = cpu_to_le16(chan->dcid);
    214f:	41 0f b7 46 1a       	movzwl 0x1a(%r14),%eax
    2154:	48 8b 75 90          	mov    -0x70(%rbp),%rsi
    2158:	66 89 06             	mov    %ax,(%rsi)
	req->flags  = cpu_to_le16(0x0000);
    215b:	31 c0                	xor    %eax,%eax
    215d:	66 89 46 02          	mov    %ax,0x2(%rsi)
	return ptr - data;
    2161:	8b 45 a8             	mov    -0x58(%rbp),%eax
}
    2164:	48 83 c4 58          	add    $0x58,%rsp
    2168:	5b                   	pop    %rbx
    2169:	41 5c                	pop    %r12
    216b:	41 5d                	pop    %r13
    216d:	41 5e                	pop    %r14
    216f:	41 5f                	pop    %r15
	return ptr - data;
    2171:	29 f0                	sub    %esi,%eax
}
    2173:	5d                   	pop    %rbp
    2174:	c3                   	retq   
    2175:	0f 1f 00             	nopl   (%rax)
			if (olen == sizeof(efs))
    2178:	41 83 fa 10          	cmp    $0x10,%r10d
    217c:	0f 84 7e 01 00 00    	je     2300 <l2cap_parse_conf_rsp+0x2c0>
			if (chan->local_stype != L2CAP_SERV_NOTRAFIC &&
    2182:	41 0f b6 86 cf 00 00 	movzbl 0xcf(%r14),%eax
    2189:	00 
    218a:	84 c0                	test   %al,%al
    218c:	74 10                	je     219e <l2cap_parse_conf_rsp+0x15e>
					efs.stype != L2CAP_SERV_NOTRAFIC &&
    218e:	0f b6 55 c1          	movzbl -0x3f(%rbp),%edx
			if (chan->local_stype != L2CAP_SERV_NOTRAFIC &&
    2192:	84 d2                	test   %dl,%dl
    2194:	74 08                	je     219e <l2cap_parse_conf_rsp+0x15e>
					efs.stype != L2CAP_SERV_NOTRAFIC &&
    2196:	38 d0                	cmp    %dl,%al
    2198:	0f 85 8e 01 00 00    	jne    232c <l2cap_parse_conf_rsp+0x2ec>
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_EFS,
    219e:	48 8d 4d c0          	lea    -0x40(%rbp),%rcx
    21a2:	48 8d 7d a8          	lea    -0x58(%rbp),%rdi
    21a6:	ba 10 00 00 00       	mov    $0x10,%edx
    21ab:	be 06 00 00 00       	mov    $0x6,%esi
    21b0:	e8 fb e3 ff ff       	callq  5b0 <l2cap_add_conf_opt>
			break;
    21b5:	e9 76 ff ff ff       	jmpq   2130 <l2cap_parse_conf_rsp+0xf0>
    21ba:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
			if (olen == sizeof(rfc))
    21c0:	41 83 fa 09          	cmp    $0x9,%r10d
    21c4:	0f 84 4e 01 00 00    	je     2318 <l2cap_parse_conf_rsp+0x2d8>
		(addr[nr / BITS_PER_LONG])) != 0;
    21ca:	49 8b 86 80 00 00 00 	mov    0x80(%r14),%rax
			if (test_bit(CONF_STATE2_DEVICE, &chan->conf_state) &&
    21d1:	a8 80                	test   $0x80,%al
    21d3:	74 0e                	je     21e3 <l2cap_parse_conf_rsp+0x1a3>
    21d5:	41 0f b6 46 24       	movzbl 0x24(%r14),%eax
    21da:	38 45 b7             	cmp    %al,-0x49(%rbp)
    21dd:	0f 85 49 01 00 00    	jne    232c <l2cap_parse_conf_rsp+0x2ec>
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC,
    21e3:	48 8d 4d b7          	lea    -0x49(%rbp),%rcx
    21e7:	48 8d 7d a8          	lea    -0x58(%rbp),%rdi
			chan->fcs = 0;
    21eb:	41 c6 46 6f 00       	movb   $0x0,0x6f(%r14)
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC,
    21f0:	ba 09 00 00 00       	mov    $0x9,%edx
    21f5:	be 04 00 00 00       	mov    $0x4,%esi
    21fa:	e8 b1 e3 ff ff       	callq  5b0 <l2cap_add_conf_opt>
			break;
    21ff:	e9 2c ff ff ff       	jmpq   2130 <l2cap_parse_conf_rsp+0xf0>
    2204:	0f 1f 40 00          	nopl   0x0(%rax)
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_FLUSH_TO,
    2208:	48 8d 7d a8          	lea    -0x58(%rbp),%rdi
			chan->flush_to = val;
    220c:	66 45 89 5e 22       	mov    %r11w,0x22(%r14)
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_FLUSH_TO,
    2211:	41 0f b7 cb          	movzwl %r11w,%ecx
    2215:	ba 02 00 00 00       	mov    $0x2,%edx
    221a:	be 02 00 00 00       	mov    $0x2,%esi
    221f:	e8 8c e3 ff ff       	callq  5b0 <l2cap_add_conf_opt>
			break;
    2224:	e9 07 ff ff ff       	jmpq   2130 <l2cap_parse_conf_rsp+0xf0>
    2229:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
			if (val < L2CAP_DEFAULT_MIN_MTU) {
    2230:	49 83 fb 2f          	cmp    $0x2f,%r11
    2234:	0f 87 b6 00 00 00    	ja     22f0 <l2cap_parse_conf_rsp+0x2b0>
				*result = L2CAP_CONF_UNACCEPT;
    223a:	48 8b 45 98          	mov    -0x68(%rbp),%rax
				chan->imtu = L2CAP_DEFAULT_MIN_MTU;
    223e:	b9 30 00 00 00       	mov    $0x30,%ecx
				*result = L2CAP_CONF_UNACCEPT;
    2243:	ba 01 00 00 00       	mov    $0x1,%edx
    2248:	66 89 10             	mov    %dx,(%rax)
				chan->imtu = L2CAP_DEFAULT_MIN_MTU;
    224b:	66 41 89 4e 1e       	mov    %cx,0x1e(%r14)
    2250:	b9 30 00 00 00       	mov    $0x30,%ecx
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_MTU, 2, chan->imtu);
    2255:	48 8d 7d a8          	lea    -0x58(%rbp),%rdi
    2259:	ba 02 00 00 00       	mov    $0x2,%edx
    225e:	be 01 00 00 00       	mov    $0x1,%esi
    2263:	e8 48 e3 ff ff       	callq  5b0 <l2cap_add_conf_opt>
			break;
    2268:	e9 c3 fe ff ff       	jmpq   2130 <l2cap_parse_conf_rsp+0xf0>
    226d:	0f 1f 00             	nopl   (%rax)
	chan->mode = rfc.mode;
    2270:	0f b6 45 b7          	movzbl -0x49(%rbp),%eax
	if (*result == L2CAP_CONF_SUCCESS || *result == L2CAP_CONF_PENDING) {
    2274:	48 8b 75 98          	mov    -0x68(%rbp),%rsi
	chan->mode = rfc.mode;
    2278:	41 88 46 24          	mov    %al,0x24(%r14)
	if (*result == L2CAP_CONF_SUCCESS || *result == L2CAP_CONF_PENDING) {
    227c:	66 f7 06 fb ff       	testw  $0xfffb,(%rsi)
    2281:	0f 85 c8 fe ff ff    	jne    214f <l2cap_parse_conf_rsp+0x10f>
		switch (rfc.mode) {
    2287:	3c 03                	cmp    $0x3,%al
    2289:	0f 84 b1 00 00 00    	je     2340 <l2cap_parse_conf_rsp+0x300>
    228f:	3c 04                	cmp    $0x4,%al
    2291:	0f 85 b8 fe ff ff    	jne    214f <l2cap_parse_conf_rsp+0x10f>
			chan->mps    = le16_to_cpu(rfc.max_pdu_size);
    2297:	0f b7 45 be          	movzwl -0x42(%rbp),%eax
    229b:	66 41 89 46 7a       	mov    %ax,0x7a(%r14)
    22a0:	e9 aa fe ff ff       	jmpq   214f <l2cap_parse_conf_rsp+0x10f>
    22a5:	0f 1f 00             	nopl   (%rax)
	switch (opt->len) {
    22a8:	3c 01                	cmp    $0x1,%al
    22aa:	75 34                	jne    22e0 <l2cap_parse_conf_rsp+0x2a0>
		*val = *((u8 *) opt->val);
    22ac:	45 0f b6 5b 02       	movzbl 0x2(%r11),%r11d
    22b1:	e9 25 fe ff ff       	jmpq   20db <l2cap_parse_conf_rsp+0x9b>
    22b6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    22bd:	00 00 00 
		*val = get_unaligned_le16(opt->val);
    22c0:	45 0f b7 5b 02       	movzwl 0x2(%r11),%r11d
    22c5:	e9 11 fe ff ff       	jmpq   20db <l2cap_parse_conf_rsp+0x9b>
    22ca:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		*val = get_unaligned_le32(opt->val);
    22d0:	45 8b 5b 02          	mov    0x2(%r11),%r11d
    22d4:	e9 02 fe ff ff       	jmpq   20db <l2cap_parse_conf_rsp+0x9b>
    22d9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		*val = (unsigned long) opt->val;
    22e0:	49 83 c3 02          	add    $0x2,%r11
    22e4:	e9 f2 fd ff ff       	jmpq   20db <l2cap_parse_conf_rsp+0x9b>
    22e9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
				chan->imtu = val;
    22f0:	66 45 89 5e 1e       	mov    %r11w,0x1e(%r14)
    22f5:	41 0f b7 cb          	movzwl %r11w,%ecx
    22f9:	e9 57 ff ff ff       	jmpq   2255 <l2cap_parse_conf_rsp+0x215>
    22fe:	66 90                	xchg   %ax,%ax
				memcpy(&efs, (void *)val, olen);
    2300:	49 8b 03             	mov    (%r11),%rax
    2303:	49 8b 53 08          	mov    0x8(%r11),%rdx
    2307:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    230b:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    230f:	e9 6e fe ff ff       	jmpq   2182 <l2cap_parse_conf_rsp+0x142>
    2314:	0f 1f 40 00          	nopl   0x0(%rax)
				memcpy(&rfc, (void *)val, olen);
    2318:	49 8b 03             	mov    (%r11),%rax
    231b:	48 89 45 b7          	mov    %rax,-0x49(%rbp)
    231f:	41 0f b6 43 08       	movzbl 0x8(%r11),%eax
    2324:	88 45 bf             	mov    %al,-0x41(%rbp)
    2327:	e9 9e fe ff ff       	jmpq   21ca <l2cap_parse_conf_rsp+0x18a>
}
    232c:	48 83 c4 58          	add    $0x58,%rsp
				return -ECONNREFUSED;
    2330:	b8 91 ff ff ff       	mov    $0xffffff91,%eax
}
    2335:	5b                   	pop    %rbx
    2336:	41 5c                	pop    %r12
    2338:	41 5d                	pop    %r13
    233a:	41 5e                	pop    %r14
    233c:	41 5f                	pop    %r15
    233e:	5d                   	pop    %rbp
    233f:	c3                   	retq   
			chan->retrans_timeout = le16_to_cpu(rfc.retrans_timeout);
    2340:	0f b7 45 ba          	movzwl -0x46(%rbp),%eax
    2344:	66 41 89 46 76       	mov    %ax,0x76(%r14)
			chan->monitor_timeout = le16_to_cpu(rfc.monitor_timeout);
    2349:	0f b7 45 bc          	movzwl -0x44(%rbp),%eax
    234d:	66 41 89 46 78       	mov    %ax,0x78(%r14)
			chan->mps    = le16_to_cpu(rfc.max_pdu_size);
    2352:	0f b7 45 be          	movzwl -0x42(%rbp),%eax
    2356:	66 41 89 46 7a       	mov    %ax,0x7a(%r14)
    235b:	49 8b 86 90 00 00 00 	mov    0x90(%r14),%rax
			if (test_bit(FLAG_EFS_ENABLE, &chan->flags)) {
    2362:	a8 20                	test   $0x20,%al
    2364:	0f 84 e5 fd ff ff    	je     214f <l2cap_parse_conf_rsp+0x10f>
				chan->local_msdu = le16_to_cpu(efs.msdu);
    236a:	0f b7 45 c2          	movzwl -0x3e(%rbp),%eax
    236e:	66 41 89 86 d0 00 00 	mov    %ax,0xd0(%r14)
    2375:	00 
				chan->local_sdu_itime =
    2376:	8b 45 c4             	mov    -0x3c(%rbp),%eax
    2379:	41 89 86 d4 00 00 00 	mov    %eax,0xd4(%r14)
				chan->local_acc_lat = le32_to_cpu(efs.acc_lat);
    2380:	8b 45 c8             	mov    -0x38(%rbp),%eax
    2383:	41 89 86 d8 00 00 00 	mov    %eax,0xd8(%r14)
				chan->local_flush_to =
    238a:	8b 45 cc             	mov    -0x34(%rbp),%eax
    238d:	41 89 86 dc 00 00 00 	mov    %eax,0xdc(%r14)
    2394:	e9 b6 fd ff ff       	jmpq   214f <l2cap_parse_conf_rsp+0x10f>
	*type = opt->type;
    2399:	41 0f b6 d1          	movzbl %r9b,%edx
	BT_DBG("type 0x%2.2x len %d val 0x%lx", *type, opt->len, *val);
    239d:	4d 89 d8             	mov    %r11,%r8
    23a0:	44 89 d1             	mov    %r10d,%ecx
    23a3:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    23aa:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    23b1:	31 c0                	xor    %eax,%eax
	*type = opt->type;
    23b3:	44 89 4d 88          	mov    %r9d,-0x78(%rbp)
	BT_DBG("type 0x%2.2x len %d val 0x%lx", *type, opt->len, *val);
    23b7:	4c 89 5d 80          	mov    %r11,-0x80(%rbp)
    23bb:	44 89 55 8c          	mov    %r10d,-0x74(%rbp)
    23bf:	e8 00 00 00 00       	callq  23c4 <l2cap_parse_conf_rsp+0x384>
    23c4:	44 8b 4d 88          	mov    -0x78(%rbp),%r9d
    23c8:	4c 8b 5d 80          	mov    -0x80(%rbp),%r11
    23cc:	44 8b 55 8c          	mov    -0x74(%rbp),%r10d
    23d0:	e9 13 fd ff ff       	jmpq   20e8 <l2cap_parse_conf_rsp+0xa8>
	BT_DBG("chan %p, rsp %p, len %d, req %p", chan, rsp, len, data);
    23d5:	49 89 c9             	mov    %rcx,%r9
    23d8:	41 89 d0             	mov    %edx,%r8d
    23db:	48 89 f1             	mov    %rsi,%rcx
    23de:	48 89 fa             	mov    %rdi,%rdx
    23e1:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    23e8:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    23ef:	31 c0                	xor    %eax,%eax
    23f1:	e8 00 00 00 00       	callq  23f6 <l2cap_parse_conf_rsp+0x3b6>
    23f6:	e9 90 fc ff ff       	jmpq   208b <l2cap_parse_conf_rsp+0x4b>
    23fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000002400 <l2cap_clear_timer>:
{
    2400:	55                   	push   %rbp
    2401:	48 89 e5             	mov    %rsp,%rbp
    2404:	41 54                	push   %r12
    2406:	49 89 fc             	mov    %rdi,%r12
 */
static inline bool cancel_delayed_work(struct delayed_work *work)
{
	bool ret;

	ret = del_timer_sync(&work->timer);
    2409:	48 8d 7e 20          	lea    0x20(%rsi),%rdi
    240d:	53                   	push   %rbx
    240e:	48 89 f3             	mov    %rsi,%rbx
    2411:	48 83 ec 10          	sub    $0x10,%rsp
    2415:	e8 00 00 00 00       	callq  241a <l2cap_clear_timer+0x1a>
    241a:	85 c0                	test   %eax,%eax
	if (ret)
    241c:	0f 95 c0             	setne  %al
    241f:	74 11                	je     2432 <l2cap_clear_timer+0x32>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    2421:	f0 80 23 fe          	lock andb $0xfe,(%rbx)
 */
static inline int atomic_dec_and_test(atomic_t *v)
{
	unsigned char c;

	asm volatile(LOCK_PREFIX "decl %0; sete %1"
    2425:	f0 41 ff 4c 24 14    	lock decl 0x14(%r12)
    242b:	0f 94 c2             	sete   %dl
	if (atomic_dec_and_test(&c->refcnt))
    242e:	84 d2                	test   %dl,%dl
    2430:	75 0e                	jne    2440 <l2cap_clear_timer+0x40>
}
    2432:	48 83 c4 10          	add    $0x10,%rsp
    2436:	5b                   	pop    %rbx
    2437:	41 5c                	pop    %r12
    2439:	5d                   	pop    %rbp
    243a:	c3                   	retq   
    243b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		kfree(c);
    2440:	4c 89 e7             	mov    %r12,%rdi
    2443:	89 45 ec             	mov    %eax,-0x14(%rbp)
    2446:	e8 00 00 00 00       	callq  244b <l2cap_clear_timer+0x4b>
    244b:	8b 45 ec             	mov    -0x14(%rbp),%eax
}
    244e:	48 83 c4 10          	add    $0x10,%rsp
    2452:	5b                   	pop    %rbx
    2453:	41 5c                	pop    %r12
    2455:	5d                   	pop    %rbp
    2456:	c3                   	retq   
    2457:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    245e:	00 00 

0000000000002460 <l2cap_chan_ready>:
{
    2460:	55                   	push   %rbp
    2461:	48 89 e5             	mov    %rsp,%rbp
    2464:	41 55                	push   %r13
    2466:	41 54                	push   %r12
    2468:	53                   	push   %rbx
    2469:	48 83 ec 08          	sub    $0x8,%rsp
    246d:	e8 00 00 00 00       	callq  2472 <l2cap_chan_ready+0x12>
	struct sock *sk = chan->sk;
    2472:	4c 8b 27             	mov    (%rdi),%r12
    2475:	31 f6                	xor    %esi,%esi
{
    2477:	48 89 fb             	mov    %rdi,%rbx
    247a:	4c 89 e7             	mov    %r12,%rdi
    247d:	e8 00 00 00 00       	callq  2482 <l2cap_chan_ready+0x22>
	BT_DBG("sk %p, parent %p", sk, parent);
    2482:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 2489 <l2cap_chan_ready+0x29>
	parent = bt_sk(sk)->parent;
    2489:	4d 8b ac 24 a8 02 00 	mov    0x2a8(%r12),%r13
    2490:	00 
	BT_DBG("sk %p, parent %p", sk, parent);
    2491:	75 77                	jne    250a <l2cap_chan_ready+0xaa>
	ret = del_timer_sync(&work->timer);
    2493:	48 8d bb 10 01 00 00 	lea    0x110(%rbx),%rdi
	chan->conf_state = 0;
    249a:	48 c7 83 80 00 00 00 	movq   $0x0,0x80(%rbx)
    24a1:	00 00 00 00 
    24a5:	e8 00 00 00 00       	callq  24aa <l2cap_chan_ready+0x4a>
	if (ret)
    24aa:	85 c0                	test   %eax,%eax
    24ac:	74 13                	je     24c1 <l2cap_chan_ready+0x61>
    24ae:	f0 80 a3 f0 00 00 00 	lock andb $0xfe,0xf0(%rbx)
    24b5:	fe 
    24b6:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    24ba:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    24bd:	84 c0                	test   %al,%al
    24bf:	75 3f                	jne    2500 <l2cap_chan_ready+0xa0>
	__l2cap_state_change(chan, BT_CONNECTED);
    24c1:	be 01 00 00 00       	mov    $0x1,%esi
    24c6:	48 89 df             	mov    %rbx,%rdi
    24c9:	e8 c2 db ff ff       	callq  90 <__l2cap_state_change>
	sk->sk_state_change(sk);
    24ce:	4c 89 e7             	mov    %r12,%rdi
    24d1:	41 ff 94 24 58 02 00 	callq  *0x258(%r12)
    24d8:	00 
	if (parent)
    24d9:	4d 85 ed             	test   %r13,%r13
    24dc:	74 0c                	je     24ea <l2cap_chan_ready+0x8a>
		parent->sk_data_ready(parent, 0);
    24de:	31 f6                	xor    %esi,%esi
    24e0:	4c 89 ef             	mov    %r13,%rdi
    24e3:	41 ff 95 60 02 00 00 	callq  *0x260(%r13)
	release_sock(sk);
    24ea:	4c 89 e7             	mov    %r12,%rdi
    24ed:	e8 00 00 00 00       	callq  24f2 <l2cap_chan_ready+0x92>
}
    24f2:	48 83 c4 08          	add    $0x8,%rsp
    24f6:	5b                   	pop    %rbx
    24f7:	41 5c                	pop    %r12
    24f9:	41 5d                	pop    %r13
    24fb:	5d                   	pop    %rbp
    24fc:	c3                   	retq   
    24fd:	0f 1f 00             	nopl   (%rax)
		kfree(c);
    2500:	48 89 df             	mov    %rbx,%rdi
    2503:	e8 00 00 00 00       	callq  2508 <l2cap_chan_ready+0xa8>
    2508:	eb b7                	jmp    24c1 <l2cap_chan_ready+0x61>
	BT_DBG("sk %p, parent %p", sk, parent);
    250a:	4c 89 e9             	mov    %r13,%rcx
    250d:	4c 89 e2             	mov    %r12,%rdx
    2510:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    2517:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    251e:	31 c0                	xor    %eax,%eax
    2520:	e8 00 00 00 00       	callq  2525 <l2cap_chan_ready+0xc5>
    2525:	e9 69 ff ff ff       	jmpq   2493 <l2cap_chan_ready+0x33>
    252a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000002530 <l2cap_drop_acked_frames>:
{
    2530:	55                   	push   %rbp
    2531:	48 89 e5             	mov    %rsp,%rbp
    2534:	41 54                	push   %r12
    2536:	53                   	push   %rbx
    2537:	e8 00 00 00 00       	callq  253c <l2cap_drop_acked_frames+0xc>
	struct sk_buff *skb = list_->next;
    253c:	48 8b 87 b8 02 00 00 	mov    0x2b8(%rdi),%rax
	while ((skb = skb_peek(&chan->tx_q)) &&
    2543:	4c 8d a7 b8 02 00 00 	lea    0x2b8(%rdi),%r12
{
    254a:	48 89 fb             	mov    %rdi,%rbx
	if (skb == (struct sk_buff *)list_)
    254d:	49 39 c4             	cmp    %rax,%r12
    2550:	74 6e                	je     25c0 <l2cap_drop_acked_frames+0x90>
	while ((skb = skb_peek(&chan->tx_q)) &&
    2552:	48 85 c0             	test   %rax,%rax
    2555:	74 69                	je     25c0 <l2cap_drop_acked_frames+0x90>
    2557:	66 83 bf a8 00 00 00 	cmpw   $0x0,0xa8(%rdi)
    255e:	00 
    255f:	74 6b                	je     25cc <l2cap_drop_acked_frames+0x9c>
		if (bt_cb(skb)->control.txseq == chan->expected_ack_seq)
    2561:	0f b7 b7 9a 00 00 00 	movzwl 0x9a(%rdi),%esi
    2568:	66 39 70 34          	cmp    %si,0x34(%rax)
    256c:	74 44                	je     25b2 <l2cap_drop_acked_frames+0x82>
		skb = skb_dequeue(&chan->tx_q);
    256e:	4c 89 e7             	mov    %r12,%rdi
    2571:	e8 00 00 00 00       	callq  2576 <l2cap_drop_acked_frames+0x46>
		kfree_skb(skb);
    2576:	48 89 c7             	mov    %rax,%rdi
    2579:	e8 00 00 00 00       	callq  257e <l2cap_drop_acked_frames+0x4e>
		chan->unacked_frames--;
    257e:	0f b7 83 a8 00 00 00 	movzwl 0xa8(%rbx),%eax
    2585:	8d 50 ff             	lea    -0x1(%rax),%edx
	struct sk_buff *skb = list_->next;
    2588:	48 8b 83 b8 02 00 00 	mov    0x2b8(%rbx),%rax
    258f:	66 89 93 a8 00 00 00 	mov    %dx,0xa8(%rbx)
	if (skb == (struct sk_buff *)list_)
    2596:	4c 39 e0             	cmp    %r12,%rax
    2599:	74 2c                	je     25c7 <l2cap_drop_acked_frames+0x97>
	while ((skb = skb_peek(&chan->tx_q)) &&
    259b:	48 85 c0             	test   %rax,%rax
    259e:	74 27                	je     25c7 <l2cap_drop_acked_frames+0x97>
    25a0:	66 85 d2             	test   %dx,%dx
    25a3:	74 27                	je     25cc <l2cap_drop_acked_frames+0x9c>
		if (bt_cb(skb)->control.txseq == chan->expected_ack_seq)
    25a5:	0f b7 8b 9a 00 00 00 	movzwl 0x9a(%rbx),%ecx
    25ac:	66 39 48 34          	cmp    %cx,0x34(%rax)
    25b0:	75 bc                	jne    256e <l2cap_drop_acked_frames+0x3e>
}
    25b2:	5b                   	pop    %rbx
    25b3:	41 5c                	pop    %r12
    25b5:	5d                   	pop    %rbp
    25b6:	c3                   	retq   
    25b7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    25be:	00 00 
    25c0:	0f b7 93 a8 00 00 00 	movzwl 0xa8(%rbx),%edx
	if (!chan->unacked_frames)
    25c7:	66 85 d2             	test   %dx,%dx
    25ca:	75 e6                	jne    25b2 <l2cap_drop_acked_frames+0x82>
	ret = del_timer_sync(&work->timer);
    25cc:	48 8d bb 80 01 00 00 	lea    0x180(%rbx),%rdi
    25d3:	e8 00 00 00 00       	callq  25d8 <l2cap_drop_acked_frames+0xa8>
	if (ret)
    25d8:	85 c0                	test   %eax,%eax
    25da:	74 d6                	je     25b2 <l2cap_drop_acked_frames+0x82>
    25dc:	f0 80 a3 60 01 00 00 	lock andb $0xfe,0x160(%rbx)
    25e3:	fe 
    25e4:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    25e8:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    25eb:	84 c0                	test   %al,%al
    25ed:	74 c3                	je     25b2 <l2cap_drop_acked_frames+0x82>
		kfree(c);
    25ef:	48 89 df             	mov    %rbx,%rdi
    25f2:	e8 00 00 00 00       	callq  25f7 <l2cap_drop_acked_frames+0xc7>
    25f7:	eb b9                	jmp    25b2 <l2cap_drop_acked_frames+0x82>
    25f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000002600 <l2cap_send_disconn_req>:
{
    2600:	55                   	push   %rbp
    2601:	48 89 e5             	mov    %rsp,%rbp
    2604:	41 56                	push   %r14
    2606:	41 55                	push   %r13
    2608:	41 54                	push   %r12
    260a:	53                   	push   %rbx
    260b:	48 83 ec 10          	sub    $0x10,%rsp
    260f:	e8 00 00 00 00       	callq  2614 <l2cap_send_disconn_req+0x14>
	struct sock *sk = chan->sk;
    2614:	4c 8b 2e             	mov    (%rsi),%r13
	if (!conn)
    2617:	48 85 ff             	test   %rdi,%rdi
{
    261a:	49 89 fc             	mov    %rdi,%r12
    261d:	48 89 f3             	mov    %rsi,%rbx
    2620:	41 89 d6             	mov    %edx,%r14d
	if (!conn)
    2623:	74 60                	je     2685 <l2cap_send_disconn_req+0x85>
	if (chan->mode == L2CAP_MODE_ERTM) {
    2625:	80 7e 24 03          	cmpb   $0x3,0x24(%rsi)
    2629:	74 6d                	je     2698 <l2cap_send_disconn_req+0x98>
	req.dcid = cpu_to_le16(chan->dcid);
    262b:	0f b7 43 1a          	movzwl 0x1a(%rbx),%eax
	l2cap_send_cmd(conn, l2cap_get_ident(conn),
    262f:	4c 89 e7             	mov    %r12,%rdi
	req.dcid = cpu_to_le16(chan->dcid);
    2632:	66 89 45 dc          	mov    %ax,-0x24(%rbp)
	req.scid = cpu_to_le16(chan->scid);
    2636:	0f b7 43 1c          	movzwl 0x1c(%rbx),%eax
    263a:	66 89 45 de          	mov    %ax,-0x22(%rbp)
	l2cap_send_cmd(conn, l2cap_get_ident(conn),
    263e:	e8 6d de ff ff       	callq  4b0 <l2cap_get_ident>
    2643:	4c 8d 45 dc          	lea    -0x24(%rbp),%r8
    2647:	0f b6 f0             	movzbl %al,%esi
    264a:	b9 04 00 00 00       	mov    $0x4,%ecx
    264f:	ba 06 00 00 00       	mov    $0x6,%edx
    2654:	4c 89 e7             	mov    %r12,%rdi
    2657:	e8 64 ed ff ff       	callq  13c0 <l2cap_send_cmd>
    265c:	31 f6                	xor    %esi,%esi
    265e:	4c 89 ef             	mov    %r13,%rdi
    2661:	e8 00 00 00 00       	callq  2666 <l2cap_send_disconn_req+0x66>
	__l2cap_state_change(chan, BT_DISCONN);
    2666:	48 89 df             	mov    %rbx,%rdi
    2669:	be 08 00 00 00       	mov    $0x8,%esi
    266e:	e8 1d da ff ff       	callq  90 <__l2cap_state_change>
static void l2cap_send_disconn_req(struct l2cap_conn *conn, struct l2cap_chan *chan, int err)
    2673:	48 8b 03             	mov    (%rbx),%rax
	release_sock(sk);
    2676:	4c 89 ef             	mov    %r13,%rdi
	sk->sk_err = err;
    2679:	44 89 b0 7c 01 00 00 	mov    %r14d,0x17c(%rax)
	release_sock(sk);
    2680:	e8 00 00 00 00       	callq  2685 <l2cap_send_disconn_req+0x85>
}
    2685:	48 83 c4 10          	add    $0x10,%rsp
    2689:	5b                   	pop    %rbx
    268a:	41 5c                	pop    %r12
    268c:	41 5d                	pop    %r13
    268e:	41 5e                	pop    %r14
    2690:	5d                   	pop    %rbp
    2691:	c3                   	retq   
    2692:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
	ret = del_timer_sync(&work->timer);
    2698:	48 8d be 80 01 00 00 	lea    0x180(%rsi),%rdi
    269f:	e8 00 00 00 00       	callq  26a4 <l2cap_send_disconn_req+0xa4>
	if (ret)
    26a4:	85 c0                	test   %eax,%eax
    26a6:	74 13                	je     26bb <l2cap_send_disconn_req+0xbb>
    26a8:	f0 80 a3 60 01 00 00 	lock andb $0xfe,0x160(%rbx)
    26af:	fe 
    26b0:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    26b4:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    26b7:	84 c0                	test   %al,%al
    26b9:	75 75                	jne    2730 <l2cap_send_disconn_req+0x130>
	ret = del_timer_sync(&work->timer);
    26bb:	48 8d bb f0 01 00 00 	lea    0x1f0(%rbx),%rdi
    26c2:	e8 00 00 00 00       	callq  26c7 <l2cap_send_disconn_req+0xc7>
	if (ret)
    26c7:	85 c0                	test   %eax,%eax
    26c9:	74 13                	je     26de <l2cap_send_disconn_req+0xde>
    26cb:	f0 80 a3 d0 01 00 00 	lock andb $0xfe,0x1d0(%rbx)
    26d2:	fe 
    26d3:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    26d7:	0f 94 c0             	sete   %al
    26da:	84 c0                	test   %al,%al
    26dc:	75 42                	jne    2720 <l2cap_send_disconn_req+0x120>
	ret = del_timer_sync(&work->timer);
    26de:	48 8d bb 60 02 00 00 	lea    0x260(%rbx),%rdi
    26e5:	e8 00 00 00 00       	callq  26ea <l2cap_send_disconn_req+0xea>
	if (ret)
    26ea:	85 c0                	test   %eax,%eax
    26ec:	0f 84 39 ff ff ff    	je     262b <l2cap_send_disconn_req+0x2b>
    26f2:	f0 80 a3 40 02 00 00 	lock andb $0xfe,0x240(%rbx)
    26f9:	fe 
    26fa:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    26fe:	0f 94 c0             	sete   %al
    2701:	84 c0                	test   %al,%al
    2703:	0f 84 22 ff ff ff    	je     262b <l2cap_send_disconn_req+0x2b>
		kfree(c);
    2709:	48 89 df             	mov    %rbx,%rdi
    270c:	e8 00 00 00 00       	callq  2711 <l2cap_send_disconn_req+0x111>
    2711:	e9 15 ff ff ff       	jmpq   262b <l2cap_send_disconn_req+0x2b>
    2716:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    271d:	00 00 00 
    2720:	48 89 df             	mov    %rbx,%rdi
    2723:	e8 00 00 00 00       	callq  2728 <l2cap_send_disconn_req+0x128>
    2728:	eb b4                	jmp    26de <l2cap_send_disconn_req+0xde>
    272a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    2730:	48 89 df             	mov    %rbx,%rdi
    2733:	e8 00 00 00 00       	callq  2738 <l2cap_send_disconn_req+0x138>
    2738:	eb 81                	jmp    26bb <l2cap_send_disconn_req+0xbb>
    273a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000002740 <l2cap_config_req>:
{
    2740:	55                   	push   %rbp
    2741:	48 89 e5             	mov    %rsp,%rbp
    2744:	41 57                	push   %r15
    2746:	41 89 d7             	mov    %edx,%r15d
    2749:	41 56                	push   %r14
    274b:	49 89 ce             	mov    %rcx,%r14
    274e:	41 55                	push   %r13
    2750:	49 89 f5             	mov    %rsi,%r13
    2753:	41 54                	push   %r12
    2755:	49 89 fc             	mov    %rdi,%r12
    2758:	53                   	push   %rbx
    2759:	48 81 ec a8 00 00 00 	sub    $0xa8,%rsp
	dcid  = __le16_to_cpu(req->dcid);
    2760:	0f b7 19             	movzwl (%rcx),%ebx
{
    2763:	65 48 8b 04 25 28 00 	mov    %gs:0x28,%rax
    276a:	00 00 
    276c:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    2770:	31 c0                	xor    %eax,%eax
	flags = __le16_to_cpu(req->flags);
    2772:	0f b7 41 02          	movzwl 0x2(%rcx),%eax
	BT_DBG("dcid 0x%4.4x flags 0x%2.2x", dcid, flags);
    2776:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 277d <l2cap_config_req+0x3d>
	flags = __le16_to_cpu(req->flags);
    277d:	66 89 85 3e ff ff ff 	mov    %ax,-0xc2(%rbp)
	BT_DBG("dcid 0x%4.4x flags 0x%2.2x", dcid, flags);
    2784:	0f 85 9c 02 00 00    	jne    2a26 <l2cap_config_req+0x2e6>
	chan = l2cap_get_chan_by_scid(conn, dcid);
    278a:	89 de                	mov    %ebx,%esi
    278c:	4c 89 e7             	mov    %r12,%rdi
    278f:	e8 fc d9 ff ff       	callq  190 <l2cap_get_chan_by_scid>
	if (!chan)
    2794:	48 85 c0             	test   %rax,%rax
	chan = l2cap_get_chan_by_scid(conn, dcid);
    2797:	48 89 c3             	mov    %rax,%rbx
	if (!chan)
    279a:	0f 84 ff 01 00 00    	je     299f <l2cap_config_req+0x25f>
	if (chan->state != BT_CONFIG && chan->state != BT_CONNECT2) {
    27a0:	0f b6 40 10          	movzbl 0x10(%rax),%eax
    27a4:	83 e8 06             	sub    $0x6,%eax
    27a7:	3c 01                	cmp    $0x1,%al
    27a9:	76 7d                	jbe    2828 <l2cap_config_req+0xe8>
		rej.reason = cpu_to_le16(L2CAP_REJ_INVALID_CID);
    27ab:	b8 02 00 00 00       	mov    $0x2,%eax
		l2cap_send_cmd(conn, cmd->ident, L2CAP_COMMAND_REJ,
    27b0:	41 0f b6 75 01       	movzbl 0x1(%r13),%esi
    27b5:	4c 8d 85 42 ff ff ff 	lea    -0xbe(%rbp),%r8
		rej.reason = cpu_to_le16(L2CAP_REJ_INVALID_CID);
    27bc:	66 89 85 42 ff ff ff 	mov    %ax,-0xbe(%rbp)
		rej.scid = cpu_to_le16(chan->scid);
    27c3:	0f b7 43 1c          	movzwl 0x1c(%rbx),%eax
		l2cap_send_cmd(conn, cmd->ident, L2CAP_COMMAND_REJ,
    27c7:	4c 89 e7             	mov    %r12,%rdi
    27ca:	b9 06 00 00 00       	mov    $0x6,%ecx
    27cf:	ba 01 00 00 00       	mov    $0x1,%edx
	int len, err = 0;
    27d4:	45 31 e4             	xor    %r12d,%r12d
		rej.scid = cpu_to_le16(chan->scid);
    27d7:	66 89 85 44 ff ff ff 	mov    %ax,-0xbc(%rbp)
		rej.dcid = cpu_to_le16(chan->dcid);
    27de:	0f b7 43 1a          	movzwl 0x1a(%rbx),%eax
    27e2:	66 89 85 46 ff ff ff 	mov    %ax,-0xba(%rbp)
		l2cap_send_cmd(conn, cmd->ident, L2CAP_COMMAND_REJ,
    27e9:	e8 d2 eb ff ff       	callq  13c0 <l2cap_send_cmd>
	mutex_unlock(&chan->lock);
    27ee:	48 8d bb 48 03 00 00 	lea    0x348(%rbx),%rdi
    27f5:	e8 00 00 00 00       	callq  27fa <l2cap_config_req+0xba>
	return err;
    27fa:	44 89 e0             	mov    %r12d,%eax
}
    27fd:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    2801:	65 48 33 0c 25 28 00 	xor    %gs:0x28,%rcx
    2808:	00 00 
    280a:	0f 85 11 02 00 00    	jne    2a21 <l2cap_config_req+0x2e1>
    2810:	48 81 c4 a8 00 00 00 	add    $0xa8,%rsp
    2817:	5b                   	pop    %rbx
    2818:	41 5c                	pop    %r12
    281a:	41 5d                	pop    %r13
    281c:	41 5e                	pop    %r14
    281e:	41 5f                	pop    %r15
    2820:	5d                   	pop    %rbp
    2821:	c3                   	retq   
    2822:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
	len = cmd_len - sizeof(*req);
    2828:	45 0f b7 ff          	movzwl %r15w,%r15d
	if (len < 0 || chan->conf_len + len > sizeof(chan->conf_req)) {
    282c:	41 83 ef 04          	sub    $0x4,%r15d
    2830:	78 0f                	js     2841 <l2cap_config_req+0x101>
    2832:	0f b6 43 6c          	movzbl 0x6c(%rbx),%eax
    2836:	0f b6 d0             	movzbl %al,%edx
    2839:	44 01 fa             	add    %r15d,%edx
    283c:	83 fa 40             	cmp    $0x40,%edx
    283f:	76 3f                	jbe    2880 <l2cap_config_req+0x140>
				l2cap_build_conf_rsp(chan, rsp,
    2841:	0f b7 8d 3e ff ff ff 	movzwl -0xc2(%rbp),%ecx
    2848:	ba 02 00 00 00       	mov    $0x2,%edx
					l2cap_build_conf_rsp(chan, rsp,
    284d:	48 8d b5 48 ff ff ff 	lea    -0xb8(%rbp),%rsi
    2854:	48 89 df             	mov    %rbx,%rdi
    2857:	e8 c4 d8 ff ff       	callq  120 <l2cap_build_conf_rsp>
		l2cap_send_cmd(conn, cmd->ident, L2CAP_CONF_RSP,
    285c:	41 0f b6 75 01       	movzbl 0x1(%r13),%esi
    2861:	4c 8d 85 48 ff ff ff 	lea    -0xb8(%rbp),%r8
    2868:	0f b7 c8             	movzwl %ax,%ecx
    286b:	ba 05 00 00 00       	mov    $0x5,%edx
    2870:	4c 89 e7             	mov    %r12,%rdi
    2873:	e8 48 eb ff ff       	callq  13c0 <l2cap_send_cmd>
	int len, err = 0;
    2878:	45 31 e4             	xor    %r12d,%r12d
    287b:	e9 6e ff ff ff       	jmpq   27ee <l2cap_config_req+0xae>
	memcpy(chan->conf_req + chan->conf_len, req->data, len);
    2880:	48 8d 7c 03 2c       	lea    0x2c(%rbx,%rax,1),%rdi
    2885:	49 8d 76 04          	lea    0x4(%r14),%rsi
    2889:	49 63 d7             	movslq %r15d,%rdx
    288c:	e8 00 00 00 00       	callq  2891 <l2cap_config_req+0x151>
	chan->conf_len += len;
    2891:	44 00 7b 6c          	add    %r15b,0x6c(%rbx)
	if (flags & 0x0001) {
    2895:	f6 85 3e ff ff ff 01 	testb  $0x1,-0xc2(%rbp)
				l2cap_build_conf_rsp(chan, rsp,
    289c:	b9 01 00 00 00       	mov    $0x1,%ecx
	if (flags & 0x0001) {
    28a1:	0f 85 d9 00 00 00    	jne    2980 <l2cap_config_req+0x240>
	len = l2cap_parse_conf_req(chan, rsp);
    28a7:	48 8d b5 48 ff ff ff 	lea    -0xb8(%rbp),%rsi
    28ae:	48 89 df             	mov    %rbx,%rdi
    28b1:	e8 5a f1 ff ff       	callq  1a10 <l2cap_parse_conf_req>
	if (len < 0) {
    28b6:	85 c0                	test   %eax,%eax
    28b8:	0f 88 c9 00 00 00    	js     2987 <l2cap_config_req+0x247>
	l2cap_send_cmd(conn, cmd->ident, L2CAP_CONF_RSP, len, rsp);
    28be:	41 0f b6 75 01       	movzbl 0x1(%r13),%esi
    28c3:	4c 8d 85 48 ff ff ff 	lea    -0xb8(%rbp),%r8
    28ca:	0f b7 c8             	movzwl %ax,%ecx
    28cd:	ba 05 00 00 00       	mov    $0x5,%edx
    28d2:	4c 89 e7             	mov    %r12,%rdi
    28d5:	e8 e6 ea ff ff       	callq  13c0 <l2cap_send_cmd>
		(addr[nr / BITS_PER_LONG])) != 0;
    28da:	48 8b 83 80 00 00 00 	mov    0x80(%rbx),%rax
	chan->num_conf_rsp++;
    28e1:	80 43 6e 01          	addb   $0x1,0x6e(%rbx)
	chan->conf_len = 0;
    28e5:	c6 43 6c 00          	movb   $0x0,0x6c(%rbx)
	if (!test_bit(CONF_OUTPUT_DONE, &chan->conf_state))
    28e9:	a8 04                	test   $0x4,%al
    28eb:	74 8b                	je     2878 <l2cap_config_req+0x138>
    28ed:	48 8b 83 80 00 00 00 	mov    0x80(%rbx),%rax
	if (test_bit(CONF_INPUT_DONE, &chan->conf_state)) {
    28f4:	a8 02                	test   $0x2,%al
    28f6:	74 3f                	je     2937 <l2cap_config_req+0x1f7>
	if (chan->mode != L2CAP_MODE_ERTM && chan->mode != L2CAP_MODE_STREAMING)
    28f8:	0f b6 43 24          	movzbl 0x24(%rbx),%eax
    28fc:	83 e8 03             	sub    $0x3,%eax
    28ff:	3c 01                	cmp    $0x1,%al
    2901:	0f 86 da 00 00 00    	jbe    29e1 <l2cap_config_req+0x2a1>
		chan->fcs = L2CAP_FCS_NONE;
    2907:	c6 43 6f 00          	movb   $0x0,0x6f(%rbx)
		l2cap_state_change(chan, BT_CONNECTED);
    290b:	be 01 00 00 00       	mov    $0x1,%esi
    2910:	48 89 df             	mov    %rbx,%rdi
	int len, err = 0;
    2913:	45 31 e4             	xor    %r12d,%r12d
		l2cap_state_change(chan, BT_CONNECTED);
    2916:	e8 05 de ff ff       	callq  720 <l2cap_state_change>
		if (chan->mode == L2CAP_MODE_ERTM ||
    291b:	0f b6 43 24          	movzbl 0x24(%rbx),%eax
    291f:	83 e8 03             	sub    $0x3,%eax
    2922:	3c 01                	cmp    $0x1,%al
    2924:	0f 86 cf 00 00 00    	jbe    29f9 <l2cap_config_req+0x2b9>
			l2cap_chan_ready(chan);
    292a:	48 89 df             	mov    %rbx,%rdi
    292d:	e8 2e fb ff ff       	callq  2460 <l2cap_chan_ready>
    2932:	e9 b7 fe ff ff       	jmpq   27ee <l2cap_config_req+0xae>
	asm volatile(LOCK_PREFIX "bts %2,%1\n\t"
    2937:	f0 0f ba ab 80 00 00 	lock btsl $0x0,0x80(%rbx)
    293e:	00 00 
    2940:	19 c0                	sbb    %eax,%eax
	if (!test_and_set_bit(CONF_REQ_SENT, &chan->conf_state)) {
    2942:	85 c0                	test   %eax,%eax
    2944:	74 63                	je     29a9 <l2cap_config_req+0x269>
		(addr[nr / BITS_PER_LONG])) != 0;
    2946:	48 8b 83 80 00 00 00 	mov    0x80(%rbx),%rax
	if (test_bit(CONF_REM_CONF_PEND, &chan->conf_state) &&
    294d:	f6 c4 04             	test   $0x4,%ah
    2950:	0f 84 22 ff ff ff    	je     2878 <l2cap_config_req+0x138>
    2956:	48 8b 83 80 00 00 00 	mov    0x80(%rbx),%rax
    295d:	f6 c4 02             	test   $0x2,%ah
    2960:	0f 84 12 ff ff ff    	je     2878 <l2cap_config_req+0x138>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    2966:	f0 80 a3 81 00 00 00 	lock andb $0xfd,0x81(%rbx)
    296d:	fd 
		asm volatile(LOCK_PREFIX "orb %1,%0"
    296e:	f0 80 8b 80 00 00 00 	lock orb $0x4,0x80(%rbx)
    2975:	04 
					l2cap_build_conf_rsp(chan, rsp,
    2976:	31 c9                	xor    %ecx,%ecx
    2978:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    297f:	00 
    2980:	31 d2                	xor    %edx,%edx
    2982:	e9 c6 fe ff ff       	jmpq   284d <l2cap_config_req+0x10d>
		l2cap_send_disconn_req(conn, chan, ECONNRESET);
    2987:	4c 89 e7             	mov    %r12,%rdi
    298a:	ba 68 00 00 00       	mov    $0x68,%edx
    298f:	48 89 de             	mov    %rbx,%rsi
    2992:	e8 69 fc ff ff       	callq  2600 <l2cap_send_disconn_req>
	int len, err = 0;
    2997:	45 31 e4             	xor    %r12d,%r12d
		goto unlock;
    299a:	e9 4f fe ff ff       	jmpq   27ee <l2cap_config_req+0xae>
		return -ENOENT;
    299f:	b8 fe ff ff ff       	mov    $0xfffffffe,%eax
    29a4:	e9 54 fe ff ff       	jmpq   27fd <l2cap_config_req+0xbd>
					l2cap_build_conf_req(chan, buf), buf);
    29a9:	48 8d 75 88          	lea    -0x78(%rbp),%rsi
    29ad:	48 89 df             	mov    %rbx,%rdi
    29b0:	e8 bb ec ff ff       	callq  1670 <l2cap_build_conf_req>
		l2cap_send_cmd(conn, l2cap_get_ident(conn), L2CAP_CONF_REQ,
    29b5:	4c 89 e7             	mov    %r12,%rdi
					l2cap_build_conf_req(chan, buf), buf);
    29b8:	41 89 c6             	mov    %eax,%r14d
		l2cap_send_cmd(conn, l2cap_get_ident(conn), L2CAP_CONF_REQ,
    29bb:	e8 f0 da ff ff       	callq  4b0 <l2cap_get_ident>
    29c0:	4c 8d 45 88          	lea    -0x78(%rbp),%r8
    29c4:	41 0f b7 ce          	movzwl %r14w,%ecx
    29c8:	0f b6 f0             	movzbl %al,%esi
    29cb:	ba 04 00 00 00       	mov    $0x4,%edx
    29d0:	4c 89 e7             	mov    %r12,%rdi
    29d3:	e8 e8 e9 ff ff       	callq  13c0 <l2cap_send_cmd>
		chan->num_conf_req++;
    29d8:	80 43 6d 01          	addb   $0x1,0x6d(%rbx)
    29dc:	e9 65 ff ff ff       	jmpq   2946 <l2cap_config_req+0x206>
		(addr[nr / BITS_PER_LONG])) != 0;
    29e1:	48 8b 83 80 00 00 00 	mov    0x80(%rbx),%rax
	else if (!test_bit(CONF_NO_FCS_RECV, &chan->conf_state))
    29e8:	a8 40                	test   $0x40,%al
    29ea:	0f 85 1b ff ff ff    	jne    290b <l2cap_config_req+0x1cb>
		chan->fcs = L2CAP_FCS_CRC16;
    29f0:	c6 43 6f 01          	movb   $0x1,0x6f(%rbx)
    29f4:	e9 12 ff ff ff       	jmpq   290b <l2cap_config_req+0x1cb>
			err = l2cap_ertm_init(chan);
    29f9:	48 89 df             	mov    %rbx,%rdi
    29fc:	e8 bf e2 ff ff       	callq  cc0 <l2cap_ertm_init>
		if (err < 0)
    2a01:	85 c0                	test   %eax,%eax
			err = l2cap_ertm_init(chan);
    2a03:	41 89 c4             	mov    %eax,%r12d
		if (err < 0)
    2a06:	0f 89 1e ff ff ff    	jns    292a <l2cap_config_req+0x1ea>
			l2cap_send_disconn_req(chan->conn, chan, -err);
    2a0c:	48 8b 7b 08          	mov    0x8(%rbx),%rdi
    2a10:	89 c2                	mov    %eax,%edx
    2a12:	48 89 de             	mov    %rbx,%rsi
    2a15:	f7 da                	neg    %edx
    2a17:	e8 e4 fb ff ff       	callq  2600 <l2cap_send_disconn_req>
    2a1c:	e9 cd fd ff ff       	jmpq   27ee <l2cap_config_req+0xae>
}
    2a21:	e8 00 00 00 00       	callq  2a26 <l2cap_config_req+0x2e6>
	BT_DBG("dcid 0x%4.4x flags 0x%2.2x", dcid, flags);
    2a26:	0f b7 8d 3e ff ff ff 	movzwl -0xc2(%rbp),%ecx
    2a2d:	89 da                	mov    %ebx,%edx
    2a2f:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    2a36:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    2a3d:	31 c0                	xor    %eax,%eax
    2a3f:	e8 00 00 00 00       	callq  2a44 <l2cap_config_req+0x304>
    2a44:	e9 41 fd ff ff       	jmpq   278a <l2cap_config_req+0x4a>
    2a49:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000002a50 <l2cap_ertm_send>:
{
    2a50:	55                   	push   %rbp
    2a51:	48 89 e5             	mov    %rsp,%rbp
    2a54:	41 57                	push   %r15
    2a56:	41 56                	push   %r14
    2a58:	41 55                	push   %r13
    2a5a:	41 54                	push   %r12
    2a5c:	53                   	push   %rbx
    2a5d:	48 83 ec 28          	sub    $0x28,%rsp
    2a61:	e8 00 00 00 00       	callq  2a66 <l2cap_ertm_send+0x16>
	if (chan->state != BT_CONNECTED)
    2a66:	80 7f 10 01          	cmpb   $0x1,0x10(%rdi)
		return -ENOTCONN;
    2a6a:	b8 95 ff ff ff       	mov    $0xffffff95,%eax
{
    2a6f:	49 89 ff             	mov    %rdi,%r15
	if (chan->state != BT_CONNECTED)
    2a72:	0f 85 e6 02 00 00    	jne    2d5e <l2cap_ertm_send+0x30e>
    2a78:	48 8b 97 88 00 00 00 	mov    0x88(%rdi),%rdx
		return 0;
    2a7f:	31 c0                	xor    %eax,%eax
	if (test_bit(CONN_REMOTE_BUSY, &chan->conn_state))
    2a81:	83 e2 10             	and    $0x10,%edx
    2a84:	0f 85 d4 02 00 00    	jne    2d5e <l2cap_ertm_send+0x30e>
	ret = del_timer_sync(&work->timer);
    2a8a:	48 8d 87 60 02 00 00 	lea    0x260(%rdi),%rax
    2a91:	4c 8b af b0 02 00 00 	mov    0x2b0(%rdi),%r13
    2a98:	c7 45 c4 00 00 00 00 	movl   $0x0,-0x3c(%rbp)
		__set_retrans_timer(chan);
    2a9f:	48 8d 9f 60 01 00 00 	lea    0x160(%rdi),%rbx
    2aa6:	4c 8d b7 80 01 00 00 	lea    0x180(%rdi),%r14
    2aad:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
		if (skb_queue_is_last(&chan->tx_q, skb))
    2ab1:	48 8d 87 b8 02 00 00 	lea    0x2b8(%rdi),%rax
    2ab8:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    2abc:	e9 6f 01 00 00       	jmpq   2c30 <l2cap_ertm_send+0x1e0>
    2ac1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
static inline u32 get_unaligned_le32(const void *p)
    2ac8:	8b 4a 04             	mov    0x4(%rdx),%ecx
    2acb:	49 8b 87 90 00 00 00 	mov    0x90(%r15),%rax
    2ad2:	83 e0 10             	and    $0x10,%eax
}

static inline __u32 __get_sar_mask(struct l2cap_chan *chan)
{
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
		return L2CAP_EXT_CTRL_SAR;
    2ad5:	48 83 f8 01          	cmp    $0x1,%rax
    2ad9:	19 d2                	sbb    %edx,%edx
    2adb:	81 e2 00 c0 fd ff    	and    $0xfffdc000,%edx
    2ae1:	81 c2 00 00 03 00    	add    $0x30000,%edx
		control &= __get_sar_mask(chan);
    2ae7:	21 ca                	and    %ecx,%edx
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    2ae9:	f0 41 0f ba b7 88 00 	lock btrl $0x7,0x88(%r15)
    2af0:	00 00 07 
    2af3:	19 c0                	sbb    %eax,%eax
		if (test_and_clear_bit(CONN_SEND_FBIT, &chan->conn_state))
    2af5:	85 c0                	test   %eax,%eax
    2af7:	74 18                	je     2b11 <l2cap_ertm_send+0xc1>
		(addr[nr / BITS_PER_LONG])) != 0;
    2af9:	49 8b 87 90 00 00 00 	mov    0x90(%r15),%rax
    2b00:	83 e0 10             	and    $0x10,%eax
}

static inline __u32 __set_ctrl_final(struct l2cap_chan *chan)
{
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
		return L2CAP_EXT_CTRL_FINAL;
    2b03:	48 83 f8 01          	cmp    $0x1,%rax
    2b07:	19 c0                	sbb    %eax,%eax
    2b09:	83 e0 7e             	and    $0x7e,%eax
    2b0c:	83 c0 02             	add    $0x2,%eax
			control |= __set_ctrl_final(chan);
    2b0f:	09 c2                	or     %eax,%edx
    2b11:	49 8b 8f 90 00 00 00 	mov    0x90(%r15),%rcx
		control |= __set_reqseq(chan, chan->buffer_seq);
    2b18:	41 0f b7 87 9e 00 00 	movzwl 0x9e(%r15),%eax
    2b1f:	00 
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    2b20:	83 e1 10             	and    $0x10,%ecx
    2b23:	0f 84 e7 01 00 00    	je     2d10 <l2cap_ertm_send+0x2c0>
		return (reqseq << L2CAP_EXT_CTRL_REQSEQ_SHIFT) &
    2b29:	c1 e0 02             	shl    $0x2,%eax
    2b2c:	0f b7 c0             	movzwl %ax,%eax
    2b2f:	49 8b 8f 90 00 00 00 	mov    0x90(%r15),%rcx
    2b36:	09 c2                	or     %eax,%edx
		control |= __set_txseq(chan, chan->next_tx_seq);
    2b38:	41 0f b7 87 98 00 00 	movzwl 0x98(%r15),%eax
    2b3f:	00 
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    2b40:	83 e1 10             	and    $0x10,%ecx
    2b43:	0f 84 b7 01 00 00    	je     2d00 <l2cap_ertm_send+0x2b0>
		return (txseq << L2CAP_EXT_CTRL_TXSEQ_SHIFT) &
    2b49:	c1 e0 12             	shl    $0x12,%eax
    2b4c:	09 c2                	or     %eax,%edx
		control |= __set_ctrl_sar(chan, bt_cb(skb)->control.sar);
    2b4e:	41 0f b6 45 30       	movzbl 0x30(%r13),%eax
    2b53:	c0 e8 04             	shr    $0x4,%al
    2b56:	89 c6                	mov    %eax,%esi
    2b58:	49 8b 87 90 00 00 00 	mov    0x90(%r15),%rax
    2b5f:	83 e6 03             	and    $0x3,%esi
		return (sar << L2CAP_CTRL_SAR_SHIFT) & L2CAP_CTRL_SAR;
    2b62:	89 f1                	mov    %esi,%ecx
    2b64:	c1 e1 0e             	shl    $0xe,%ecx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    2b67:	a8 10                	test   $0x10,%al
    2b69:	74 05                	je     2b70 <l2cap_ertm_send+0x120>
		return (sar << L2CAP_EXT_CTRL_SAR_SHIFT) & L2CAP_EXT_CTRL_SAR;
    2b6b:	c1 e6 10             	shl    $0x10,%esi
    2b6e:	89 f1                	mov    %esi,%ecx
    2b70:	49 8b b7 90 00 00 00 	mov    0x90(%r15),%rsi
    2b77:	09 ca                	or     %ecx,%edx
		__put_control(chan, control, tx_skb->data + L2CAP_HDR_SIZE);
    2b79:	49 8b bc 24 e0 00 00 	mov    0xe0(%r12),%rdi
    2b80:	00 
}

static inline void __put_control(struct l2cap_chan *chan, __u32 control,
								void *p)
{
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    2b81:	83 e6 10             	and    $0x10,%esi
    2b84:	0f 84 36 01 00 00    	je     2cc0 <l2cap_ertm_send+0x270>
	*((__le16 *)p) = cpu_to_le16(val);
}

static inline void put_unaligned_le32(u32 val, void *p)
{
	*((__le32 *)p) = cpu_to_le32(val);
    2b8a:	89 57 04             	mov    %edx,0x4(%rdi)
		if (chan->fcs == L2CAP_FCS_CRC16) {
    2b8d:	41 80 7f 6f 01       	cmpb   $0x1,0x6f(%r15)
    2b92:	0f 84 37 01 00 00    	je     2ccf <l2cap_ertm_send+0x27f>
		l2cap_do_send(chan, tx_skb);
    2b98:	4c 89 e6             	mov    %r12,%rsi
    2b9b:	4c 89 ff             	mov    %r15,%rdi
    2b9e:	e8 5d d9 ff ff       	callq  500 <l2cap_do_send>
		__set_retrans_timer(chan);
    2ba3:	bf d0 07 00 00       	mov    $0x7d0,%edi
    2ba8:	e8 00 00 00 00       	callq  2bad <l2cap_ertm_send+0x15d>
	BT_DBG("chan %p state %s timeout %ld", chan,
    2bad:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 2bb4 <l2cap_ertm_send+0x164>
    2bb4:	49 89 c4             	mov    %rax,%r12
    2bb7:	0f 85 0e 02 00 00    	jne    2dcb <l2cap_ertm_send+0x37b>
    2bbd:	4c 89 f7             	mov    %r14,%rdi
    2bc0:	e8 00 00 00 00       	callq  2bc5 <l2cap_ertm_send+0x175>
	if (ret)
    2bc5:	85 c0                	test   %eax,%eax
    2bc7:	0f 84 53 01 00 00    	je     2d20 <l2cap_ertm_send+0x2d0>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    2bcd:	f0 80 23 fe          	lock andb $0xfe,(%rbx)
	schedule_delayed_work(work, timeout);
    2bd1:	4c 89 e6             	mov    %r12,%rsi
    2bd4:	48 89 df             	mov    %rbx,%rdi
    2bd7:	e8 00 00 00 00       	callq  2bdc <l2cap_ertm_send+0x18c>
		bt_cb(skb)->control.txseq = chan->next_tx_seq;
    2bdc:	41 0f b7 87 98 00 00 	movzwl 0x98(%r15),%eax
    2be3:	00 
    2be4:	66 41 89 45 34       	mov    %ax,0x34(%r13)
	return (seq + 1) % (chan->tx_win_max + 1);
    2be9:	41 0f b7 87 98 00 00 	movzwl 0x98(%r15),%eax
    2bf0:	00 
    2bf1:	41 0f b7 4f 72       	movzwl 0x72(%r15),%ecx
    2bf6:	83 c0 01             	add    $0x1,%eax
    2bf9:	83 c1 01             	add    $0x1,%ecx
    2bfc:	99                   	cltd   
    2bfd:	f7 f9                	idiv   %ecx
    2bff:	66 41 89 97 98 00 00 	mov    %dx,0x98(%r15)
    2c06:	00 
		if (bt_cb(skb)->control.retries == 1) {
    2c07:	41 80 7d 36 01       	cmpb   $0x1,0x36(%r13)
    2c0c:	0f 84 1e 01 00 00    	je     2d30 <l2cap_ertm_send+0x2e0>
		chan->frames_sent++;
    2c12:	66 41 83 87 a6 00 00 	addw   $0x1,0xa6(%r15)
    2c19:	00 01 
	struct sk_buff *skb, *tx_skb;
    2c1b:	4d 8b 6d 00          	mov    0x0(%r13),%r13
		if (skb_queue_is_last(&chan->tx_q, skb))
    2c1f:	4c 3b 6d c8          	cmp    -0x38(%rbp),%r13
    2c23:	0f 84 27 01 00 00    	je     2d50 <l2cap_ertm_send+0x300>
			chan->tx_send_head = skb_queue_next(&chan->tx_q, skb);
    2c29:	4d 89 af b0 02 00 00 	mov    %r13,0x2b0(%r15)
	while ((skb = chan->tx_send_head) && (!l2cap_tx_window_full(chan))) {
    2c30:	4d 85 ed             	test   %r13,%r13
    2c33:	0f 84 22 01 00 00    	je     2d5b <l2cap_ertm_send+0x30b>
	sub = (ch->next_tx_seq - ch->expected_ack_seq) % 64;
    2c39:	41 0f b7 97 9a 00 00 	movzwl 0x9a(%r15),%edx
    2c40:	00 
    2c41:	41 0f b7 87 98 00 00 	movzwl 0x98(%r15),%eax
    2c48:	00 
    2c49:	29 d0                	sub    %edx,%eax
    2c4b:	99                   	cltd   
    2c4c:	c1 ea 1a             	shr    $0x1a,%edx
    2c4f:	01 d0                	add    %edx,%eax
    2c51:	83 e0 3f             	and    $0x3f,%eax
    2c54:	29 d0                	sub    %edx,%eax
		sub += 64;
    2c56:	8d 50 40             	lea    0x40(%rax),%edx
    2c59:	85 c0                	test   %eax,%eax
    2c5b:	0f 48 c2             	cmovs  %edx,%eax
	return sub == ch->remote_tx_win;
    2c5e:	41 0f b7 97 c8 00 00 	movzwl 0xc8(%r15),%edx
    2c65:	00 
    2c66:	39 c2                	cmp    %eax,%edx
    2c68:	0f 84 ed 00 00 00    	je     2d5b <l2cap_ertm_send+0x30b>
		if (bt_cb(skb)->control.retries == chan->remote_max_tx &&
    2c6e:	41 0f b6 45 36       	movzbl 0x36(%r13),%eax
    2c73:	41 3a 87 ca 00 00 00 	cmp    0xca(%r15),%al
    2c7a:	75 08                	jne    2c84 <l2cap_ertm_send+0x234>
    2c7c:	84 c0                	test   %al,%al
    2c7e:	0f 85 34 01 00 00    	jne    2db8 <l2cap_ertm_send+0x368>
		tx_skb = skb_clone(skb, GFP_ATOMIC);
    2c84:	be 20 00 00 00       	mov    $0x20,%esi
    2c89:	4c 89 ef             	mov    %r13,%rdi
    2c8c:	e8 00 00 00 00       	callq  2c91 <l2cap_ertm_send+0x241>
		bt_cb(skb)->control.retries++;
    2c91:	41 80 45 36 01       	addb   $0x1,0x36(%r13)
		tx_skb = skb_clone(skb, GFP_ATOMIC);
    2c96:	49 89 c4             	mov    %rax,%r12
		control = __get_control(chan, tx_skb->data + L2CAP_HDR_SIZE);
    2c99:	48 8b 90 e0 00 00 00 	mov    0xe0(%rax),%rdx
		(addr[nr / BITS_PER_LONG])) != 0;
    2ca0:	49 8b 87 90 00 00 00 	mov    0x90(%r15),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    2ca7:	a8 10                	test   $0x10,%al
    2ca9:	0f 85 19 fe ff ff    	jne    2ac8 <l2cap_ertm_send+0x78>
		return get_unaligned_le16(p);
    2caf:	0f b7 4a 04          	movzwl 0x4(%rdx),%ecx
    2cb3:	e9 13 fe ff ff       	jmpq   2acb <l2cap_ertm_send+0x7b>
    2cb8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    2cbf:	00 
    2cc0:	66 89 57 04          	mov    %dx,0x4(%rdi)
		if (chan->fcs == L2CAP_FCS_CRC16) {
    2cc4:	41 80 7f 6f 01       	cmpb   $0x1,0x6f(%r15)
    2cc9:	0f 85 c9 fe ff ff    	jne    2b98 <l2cap_ertm_send+0x148>
						tx_skb->len - L2CAP_FCS_SIZE);
    2ccf:	41 8b 44 24 68       	mov    0x68(%r12),%eax
			fcs = crc16(0, (u8 *)skb->data,
    2cd4:	49 8b b5 e0 00 00 00 	mov    0xe0(%r13),%rsi
    2cdb:	31 ff                	xor    %edi,%edi
    2cdd:	8d 50 fe             	lea    -0x2(%rax),%edx
    2ce0:	e8 00 00 00 00       	callq  2ce5 <l2cap_ertm_send+0x295>
						tx_skb->len - L2CAP_FCS_SIZE);
    2ce5:	41 8b 54 24 68       	mov    0x68(%r12),%edx
	*((__le16 *)p) = cpu_to_le16(val);
    2cea:	49 8b 8d e0 00 00 00 	mov    0xe0(%r13),%rcx
    2cf1:	66 89 44 11 fe       	mov    %ax,-0x2(%rcx,%rdx,1)
    2cf6:	e9 9d fe ff ff       	jmpq   2b98 <l2cap_ertm_send+0x148>
    2cfb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		return (txseq << L2CAP_CTRL_TXSEQ_SHIFT) & L2CAP_CTRL_TXSEQ;
    2d00:	01 c0                	add    %eax,%eax
    2d02:	83 e0 7e             	and    $0x7e,%eax
    2d05:	e9 42 fe ff ff       	jmpq   2b4c <l2cap_ertm_send+0xfc>
    2d0a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		return (reqseq << L2CAP_CTRL_REQSEQ_SHIFT) & L2CAP_CTRL_REQSEQ;
    2d10:	c1 e0 08             	shl    $0x8,%eax
    2d13:	25 00 3f 00 00       	and    $0x3f00,%eax
    2d18:	e9 12 fe ff ff       	jmpq   2b2f <l2cap_ertm_send+0xdf>
    2d1d:	0f 1f 00             	nopl   (%rax)
	asm volatile(LOCK_PREFIX "incl %0"
    2d20:	f0 41 ff 47 14       	lock incl 0x14(%r15)
    2d25:	e9 a7 fe ff ff       	jmpq   2bd1 <l2cap_ertm_send+0x181>
    2d2a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
			if (!nsent++)
    2d30:	8b 45 c4             	mov    -0x3c(%rbp),%eax
			chan->unacked_frames++;
    2d33:	66 41 83 87 a8 00 00 	addw   $0x1,0xa8(%r15)
    2d3a:	00 01 
			if (!nsent++)
    2d3c:	85 c0                	test   %eax,%eax
    2d3e:	74 30                	je     2d70 <l2cap_ertm_send+0x320>
    2d40:	83 45 c4 01          	addl   $0x1,-0x3c(%rbp)
    2d44:	e9 c9 fe ff ff       	jmpq   2c12 <l2cap_ertm_send+0x1c2>
    2d49:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
			chan->tx_send_head = NULL;
    2d50:	49 c7 87 b0 02 00 00 	movq   $0x0,0x2b0(%r15)
    2d57:	00 00 00 00 
		return 0;
    2d5b:	8b 45 c4             	mov    -0x3c(%rbp),%eax
}
    2d5e:	48 83 c4 28          	add    $0x28,%rsp
    2d62:	5b                   	pop    %rbx
    2d63:	41 5c                	pop    %r12
    2d65:	41 5d                	pop    %r13
    2d67:	41 5e                	pop    %r14
    2d69:	41 5f                	pop    %r15
    2d6b:	5d                   	pop    %rbp
    2d6c:	c3                   	retq   
    2d6d:	0f 1f 00             	nopl   (%rax)
	ret = del_timer_sync(&work->timer);
    2d70:	48 8b 7d b8          	mov    -0x48(%rbp),%rdi
    2d74:	e8 00 00 00 00       	callq  2d79 <l2cap_ertm_send+0x329>
	if (ret)
    2d79:	85 c0                	test   %eax,%eax
    2d7b:	74 15                	je     2d92 <l2cap_ertm_send+0x342>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    2d7d:	f0 41 80 a7 40 02 00 	lock andb $0xfe,0x240(%r15)
    2d84:	00 fe 
	asm volatile(LOCK_PREFIX "decl %0; sete %1"
    2d86:	f0 41 ff 4f 14       	lock decl 0x14(%r15)
    2d8b:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    2d8e:	84 c0                	test   %al,%al
    2d90:	75 0e                	jne    2da0 <l2cap_ertm_send+0x350>
		kfree(c);
    2d92:	c7 45 c4 01 00 00 00 	movl   $0x1,-0x3c(%rbp)
    2d99:	e9 74 fe ff ff       	jmpq   2c12 <l2cap_ertm_send+0x1c2>
    2d9e:	66 90                	xchg   %ax,%ax
    2da0:	4c 89 ff             	mov    %r15,%rdi
    2da3:	e8 00 00 00 00       	callq  2da8 <l2cap_ertm_send+0x358>
    2da8:	c7 45 c4 01 00 00 00 	movl   $0x1,-0x3c(%rbp)
    2daf:	e9 5e fe ff ff       	jmpq   2c12 <l2cap_ertm_send+0x1c2>
    2db4:	0f 1f 40 00          	nopl   0x0(%rax)
			l2cap_send_disconn_req(chan->conn, chan, ECONNABORTED);
    2db8:	49 8b 7f 08          	mov    0x8(%r15),%rdi
    2dbc:	ba 67 00 00 00       	mov    $0x67,%edx
    2dc1:	4c 89 fe             	mov    %r15,%rsi
    2dc4:	e8 37 f8 ff ff       	callq  2600 <l2cap_send_disconn_req>
    2dc9:	eb 90                	jmp    2d5b <l2cap_ertm_send+0x30b>
	switch (state) {
    2dcb:	41 0f b6 47 10       	movzbl 0x10(%r15),%eax
    2dd0:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    2dd7:	83 e8 01             	sub    $0x1,%eax
    2dda:	83 f8 08             	cmp    $0x8,%eax
    2ddd:	77 08                	ja     2de7 <l2cap_ertm_send+0x397>
    2ddf:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    2de6:	00 
	BT_DBG("chan %p state %s timeout %ld", chan,
    2de7:	4d 89 e0             	mov    %r12,%r8
    2dea:	4c 89 fa             	mov    %r15,%rdx
    2ded:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    2df4:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    2dfb:	31 c0                	xor    %eax,%eax
    2dfd:	e8 00 00 00 00       	callq  2e02 <l2cap_ertm_send+0x3b2>
    2e02:	e9 b6 fd ff ff       	jmpq   2bbd <l2cap_ertm_send+0x16d>
    2e07:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    2e0e:	00 00 

0000000000002e10 <l2cap_send_srejtail>:
{
    2e10:	55                   	push   %rbp
    2e11:	48 89 e5             	mov    %rsp,%rbp
    2e14:	41 57                	push   %r15
    2e16:	41 56                	push   %r14
    2e18:	41 55                	push   %r13
    2e1a:	41 54                	push   %r12
    2e1c:	53                   	push   %rbx
    2e1d:	48 83 ec 18          	sub    $0x18,%rsp
    2e21:	e8 00 00 00 00       	callq  2e26 <l2cap_send_srejtail+0x16>
		(addr[nr / BITS_PER_LONG])) != 0;
    2e26:	48 8b 87 90 00 00 00 	mov    0x90(%rdi),%rax
	control |= __set_reqseq(chan, tail->tx_seq);
    2e2d:	48 8b 8f 10 03 00 00 	mov    0x310(%rdi),%rcx
{
    2e34:	48 89 fb             	mov    %rdi,%rbx
    2e37:	48 c1 e8 04          	shr    $0x4,%rax
	control |= __set_reqseq(chan, tail->tx_seq);
    2e3b:	0f b7 49 f8          	movzwl -0x8(%rcx),%ecx
    2e3f:	83 e0 01             	and    $0x1,%eax
		return (super << L2CAP_EXT_CTRL_SUPER_SHIFT) &
    2e42:	48 83 f8 01          	cmp    $0x1,%rax
    2e46:	48 8b 87 90 00 00 00 	mov    0x90(%rdi),%rax
    2e4d:	48 8b bf 90 00 00 00 	mov    0x90(%rdi),%rdi
    2e54:	19 d2                	sbb    %edx,%edx
    2e56:	81 e2 0c 00 fd ff    	and    $0xfffd000c,%edx
		return (reqseq << L2CAP_CTRL_REQSEQ_SHIFT) & L2CAP_CTRL_REQSEQ;
    2e5c:	89 ce                	mov    %ecx,%esi
    2e5e:	48 c1 e8 04          	shr    $0x4,%rax
		return (super << L2CAP_EXT_CTRL_SUPER_SHIFT) &
    2e62:	81 c2 00 00 03 00    	add    $0x30000,%edx
    2e68:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_FINAL;
    2e6b:	48 83 f8 01          	cmp    $0x1,%rax
    2e6f:	19 c0                	sbb    %eax,%eax
		return (reqseq << L2CAP_CTRL_REQSEQ_SHIFT) & L2CAP_CTRL_REQSEQ;
    2e71:	c1 e6 08             	shl    $0x8,%esi
		return L2CAP_EXT_CTRL_FINAL;
    2e74:	83 e0 7e             	and    $0x7e,%eax
		return (reqseq << L2CAP_CTRL_REQSEQ_SHIFT) & L2CAP_CTRL_REQSEQ;
    2e77:	81 e6 00 3f 00 00    	and    $0x3f00,%esi
		return L2CAP_EXT_CTRL_FINAL;
    2e7d:	83 c0 02             	add    $0x2,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    2e80:	83 e7 10             	and    $0x10,%edi
    2e83:	74 0a                	je     2e8f <l2cap_send_srejtail+0x7f>
		return (reqseq << L2CAP_EXT_CTRL_REQSEQ_SHIFT) &
    2e85:	8d 34 8d 00 00 00 00 	lea    0x0(,%rcx,4),%esi
    2e8c:	0f b7 f6             	movzwl %si,%esi
	if (chan->state != BT_CONNECTED)
    2e8f:	80 7b 10 01          	cmpb   $0x1,0x10(%rbx)
	struct l2cap_conn *conn = chan->conn;
    2e93:	4c 8b 6b 08          	mov    0x8(%rbx),%r13
	if (chan->state != BT_CONNECTED)
    2e97:	74 17                	je     2eb0 <l2cap_send_srejtail+0xa0>
}
    2e99:	48 83 c4 18          	add    $0x18,%rsp
    2e9d:	5b                   	pop    %rbx
    2e9e:	41 5c                	pop    %r12
    2ea0:	41 5d                	pop    %r13
    2ea2:	41 5e                	pop    %r14
    2ea4:	41 5f                	pop    %r15
    2ea6:	5d                   	pop    %rbp
    2ea7:	c3                   	retq   
    2ea8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    2eaf:	00 
    2eb0:	48 8b 8b 90 00 00 00 	mov    0x90(%rbx),%rcx
    2eb7:	48 c1 e9 04          	shr    $0x4,%rcx
    2ebb:	83 e1 01             	and    $0x1,%ecx
		hlen = L2CAP_EXT_HDR_SIZE;
    2ebe:	48 83 f9 01          	cmp    $0x1,%rcx
    2ec2:	45 19 e4             	sbb    %r12d,%r12d
    2ec5:	41 83 e4 fe          	and    $0xfffffffe,%r12d
    2ec9:	41 83 c4 08          	add    $0x8,%r12d
		hlen += L2CAP_FCS_SIZE;
    2ecd:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    2ed1:	41 8d 4c 24 02       	lea    0x2(%r12),%ecx
    2ed6:	44 0f 44 e1          	cmove  %ecx,%r12d
	control |= __set_ctrl_final(chan);
    2eda:	09 d0                	or     %edx,%eax
    2edc:	41 89 c6             	mov    %eax,%r14d
	control |= __set_reqseq(chan, tail->tx_seq);
    2edf:	41 09 f6             	or     %esi,%r14d
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    2ee2:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 2ee9 <l2cap_send_srejtail+0xd9>
    2ee9:	0f 85 73 01 00 00    	jne    3062 <l2cap_send_srejtail+0x252>
	count = min_t(unsigned int, conn->mtu, hlen);
    2eef:	45 8b 7d 20          	mov    0x20(%r13),%r15d
    2ef3:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    2efa:	45 39 fc             	cmp    %r15d,%r12d
    2efd:	45 0f 46 fc          	cmovbe %r12d,%r15d
	control |= __set_sframe(chan);
    2f01:	41 83 ce 01          	or     $0x1,%r14d
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    2f05:	f0 0f ba b3 88 00 00 	lock btrl $0x7,0x88(%rbx)
    2f0c:	00 07 
    2f0e:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_FBIT, &chan->conn_state))
    2f10:	85 c0                	test   %eax,%eax
    2f12:	74 1d                	je     2f31 <l2cap_send_srejtail+0x121>
		(addr[nr / BITS_PER_LONG])) != 0;
    2f14:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    2f1b:	48 c1 e8 04          	shr    $0x4,%rax
    2f1f:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_FINAL;
    2f22:	48 83 f8 01          	cmp    $0x1,%rax
    2f26:	19 c0                	sbb    %eax,%eax
    2f28:	83 e0 7e             	and    $0x7e,%eax
    2f2b:	83 c0 02             	add    $0x2,%eax
		control |= __set_ctrl_final(chan);
    2f2e:	41 09 c6             	or     %eax,%r14d
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    2f31:	f0 0f ba b3 88 00 00 	lock btrl $0x3,0x88(%rbx)
    2f38:	00 03 
    2f3a:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_PBIT, &chan->conn_state))
    2f3c:	85 c0                	test   %eax,%eax
    2f3e:	0f 85 bc 00 00 00    	jne    3000 <l2cap_send_srejtail+0x1f0>
	if ((skb = alloc_skb(len + BT_SKB_RESERVE, how))) {
    2f44:	41 8d 7f 08          	lea    0x8(%r15),%edi
	return __alloc_skb(size, priority, 0, NUMA_NO_NODE);
    2f48:	31 d2                	xor    %edx,%edx
    2f4a:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    2f4f:	be 20 00 00 00       	mov    $0x20,%esi
    2f54:	e8 00 00 00 00       	callq  2f59 <l2cap_send_srejtail+0x149>
    2f59:	48 85 c0             	test   %rax,%rax
    2f5c:	49 89 c5             	mov    %rax,%r13
    2f5f:	0f 84 34 ff ff ff    	je     2e99 <l2cap_send_srejtail+0x89>
	skb->data += len;
    2f65:	48 83 80 e0 00 00 00 	addq   $0x8,0xe0(%rax)
    2f6c:	08 
	skb->tail += len;
    2f6d:	83 80 cc 00 00 00 08 	addl   $0x8,0xcc(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    2f74:	be 04 00 00 00       	mov    $0x4,%esi
    2f79:	48 89 c7             	mov    %rax,%rdi
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    2f7c:	41 83 ec 04          	sub    $0x4,%r12d
		bt_cb(skb)->incoming  = 0;
    2f80:	c6 40 29 00          	movb   $0x0,0x29(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    2f84:	e8 00 00 00 00       	callq  2f89 <l2cap_send_srejtail+0x179>
    2f89:	48 89 c1             	mov    %rax,%rcx
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    2f8c:	66 44 89 20          	mov    %r12w,(%rax)
	lh->cid = cpu_to_le16(chan->dcid);
    2f90:	0f b7 43 1a          	movzwl 0x1a(%rbx),%eax
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    2f94:	4c 89 ef             	mov    %r13,%rdi
	lh->cid = cpu_to_le16(chan->dcid);
    2f97:	48 89 4d c8          	mov    %rcx,-0x38(%rbp)
    2f9b:	66 89 41 02          	mov    %ax,0x2(%rcx)
		(addr[nr / BITS_PER_LONG])) != 0;
    2f9f:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
    2fa6:	48 c1 ea 04          	shr    $0x4,%rdx
    2faa:	83 e2 01             	and    $0x1,%edx
		return put_unaligned_le16(control, p);
}

static inline __u8 __ctrl_size(struct l2cap_chan *chan)
{
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    2fad:	48 83 fa 01          	cmp    $0x1,%rdx
    2fb1:	19 f6                	sbb    %esi,%esi
    2fb3:	83 e6 fe             	and    $0xfffffffe,%esi
    2fb6:	83 c6 04             	add    $0x4,%esi
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    2fb9:	e8 00 00 00 00       	callq  2fbe <l2cap_send_srejtail+0x1ae>
    2fbe:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    2fc5:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    2fc9:	83 e2 10             	and    $0x10,%edx
    2fcc:	75 62                	jne    3030 <l2cap_send_srejtail+0x220>
    2fce:	66 44 89 30          	mov    %r14w,(%rax)
	if (chan->fcs == L2CAP_FCS_CRC16) {
    2fd2:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    2fd6:	74 60                	je     3038 <l2cap_send_srejtail+0x228>
	skb->priority = HCI_PRIO_MAX;
    2fd8:	41 c7 45 78 07 00 00 	movl   $0x7,0x78(%r13)
    2fdf:	00 
	l2cap_do_send(chan, skb);
    2fe0:	4c 89 ee             	mov    %r13,%rsi
    2fe3:	48 89 df             	mov    %rbx,%rdi
    2fe6:	e8 15 d5 ff ff       	callq  500 <l2cap_do_send>
}
    2feb:	48 83 c4 18          	add    $0x18,%rsp
    2fef:	5b                   	pop    %rbx
    2ff0:	41 5c                	pop    %r12
    2ff2:	41 5d                	pop    %r13
    2ff4:	41 5e                	pop    %r14
    2ff6:	41 5f                	pop    %r15
    2ff8:	5d                   	pop    %rbp
    2ff9:	c3                   	retq   
    2ffa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    3000:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    3007:	48 c1 e8 04          	shr    $0x4,%rax
    300b:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_POLL;
    300e:	48 83 f8 01          	cmp    $0x1,%rax
    3012:	19 c0                	sbb    %eax,%eax
    3014:	25 10 00 fc ff       	and    $0xfffc0010,%eax
    3019:	05 00 00 04 00       	add    $0x40000,%eax
		control |= __set_ctrl_poll(chan);
    301e:	41 09 c6             	or     %eax,%r14d
    3021:	e9 1e ff ff ff       	jmpq   2f44 <l2cap_send_srejtail+0x134>
    3026:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    302d:	00 00 00 
	*((__le32 *)p) = cpu_to_le32(val);
    3030:	44 89 30             	mov    %r14d,(%rax)
    3033:	eb 9d                	jmp    2fd2 <l2cap_send_srejtail+0x1c2>
    3035:	0f 1f 00             	nopl   (%rax)
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    3038:	41 8d 57 fe          	lea    -0x2(%r15),%edx
    303c:	48 89 ce             	mov    %rcx,%rsi
    303f:	31 ff                	xor    %edi,%edi
    3041:	48 63 d2             	movslq %edx,%rdx
    3044:	e8 00 00 00 00       	callq  3049 <l2cap_send_srejtail+0x239>
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    3049:	be 02 00 00 00       	mov    $0x2,%esi
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    304e:	41 89 c4             	mov    %eax,%r12d
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    3051:	4c 89 ef             	mov    %r13,%rdi
    3054:	e8 00 00 00 00       	callq  3059 <l2cap_send_srejtail+0x249>
	*((__le16 *)p) = cpu_to_le16(val);
    3059:	66 44 89 20          	mov    %r12w,(%rax)
    305d:	e9 76 ff ff ff       	jmpq   2fd8 <l2cap_send_srejtail+0x1c8>
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    3062:	44 89 f1             	mov    %r14d,%ecx
    3065:	48 89 da             	mov    %rbx,%rdx
    3068:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    306f:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    3076:	31 c0                	xor    %eax,%eax
    3078:	e8 00 00 00 00       	callq  307d <l2cap_send_srejtail+0x26d>
    307d:	e9 6d fe ff ff       	jmpq   2eef <l2cap_send_srejtail+0xdf>
    3082:	0f 1f 40 00          	nopl   0x0(%rax)
    3086:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    308d:	00 00 00 

0000000000003090 <l2cap_send_srejframe>:
{
    3090:	55                   	push   %rbp
    3091:	48 89 e5             	mov    %rsp,%rbp
    3094:	41 57                	push   %r15
    3096:	41 56                	push   %r14
    3098:	41 55                	push   %r13
    309a:	41 54                	push   %r12
    309c:	53                   	push   %rbx
    309d:	48 83 ec 28          	sub    $0x28,%rsp
    30a1:	e8 00 00 00 00       	callq  30a6 <l2cap_send_srejframe+0x16>
	while (tx_seq != chan->expected_tx_seq) {
    30a6:	0f b7 8f 9c 00 00 00 	movzwl 0x9c(%rdi),%ecx
{
    30ad:	48 89 fb             	mov    %rdi,%rbx
    30b0:	41 89 f4             	mov    %esi,%r12d
	while (tx_seq != chan->expected_tx_seq) {
    30b3:	66 39 f1             	cmp    %si,%cx
    30b6:	0f 84 04 03 00 00    	je     33c0 <l2cap_send_srejframe+0x330>
		list_add_tail(&new->list, &chan->srej_l);
    30bc:	48 8d 87 08 03 00 00 	lea    0x308(%rdi),%rax
    30c3:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    30c7:	e9 b8 00 00 00       	jmpq   3184 <l2cap_send_srejframe+0xf4>
    30cc:	0f 1f 40 00          	nopl   0x0(%rax)
		return (reqseq << L2CAP_EXT_CTRL_REQSEQ_SHIFT) &
    30d0:	41 c1 e6 02          	shl    $0x2,%r14d
    30d4:	45 0f b7 f6          	movzwl %r14w,%r14d
	u16 mask = seq_list->mask;
    30d8:	44 0f b7 83 ec 02 00 	movzwl 0x2ec(%rbx),%r8d
    30df:	00 
	if (seq_list->list[seq & mask] != L2CAP_SEQ_LIST_CLEAR)
    30e0:	89 ce                	mov    %ecx,%esi
    30e2:	48 8b bb f0 02 00 00 	mov    0x2f0(%rbx),%rdi
    30e9:	44 21 c6             	and    %r8d,%esi
    30ec:	0f b7 f6             	movzwl %si,%esi
    30ef:	48 01 f6             	add    %rsi,%rsi
    30f2:	48 8d 14 37          	lea    (%rdi,%rsi,1),%rdx
    30f6:	66 83 3a ff          	cmpw   $0xffff,(%rdx)
    30fa:	0f 84 30 02 00 00    	je     3330 <l2cap_send_srejframe+0x2a0>
	if (chan->state != BT_CONNECTED)
    3100:	80 7b 10 01          	cmpb   $0x1,0x10(%rbx)
	struct l2cap_conn *conn = chan->conn;
    3104:	4c 8b 7b 08          	mov    0x8(%rbx),%r15
	if (chan->state != BT_CONNECTED)
    3108:	0f 84 ba 00 00 00    	je     31c8 <l2cap_send_srejframe+0x138>
	return kmalloc_caches[index];
    310e:	48 8b 3d 00 00 00 00 	mov    0x0(%rip),%rdi        # 3115 <l2cap_send_srejframe+0x85>
			if (!s)
    3115:	48 85 ff             	test   %rdi,%rdi
    3118:	0f 84 02 02 00 00    	je     3320 <l2cap_send_srejframe+0x290>
			return kmem_cache_alloc_trace(s, flags, size);
    311e:	ba 18 00 00 00       	mov    $0x18,%edx
    3123:	be 20 80 00 00       	mov    $0x8020,%esi
    3128:	e8 00 00 00 00       	callq  312d <l2cap_send_srejframe+0x9d>
		if (!new)
    312d:	48 85 c0             	test   %rax,%rax
    3130:	48 89 c7             	mov    %rax,%rdi
    3133:	0f 84 b7 02 00 00    	je     33f0 <l2cap_send_srejframe+0x360>
		new->tx_seq = chan->expected_tx_seq;
    3139:	0f b7 83 9c 00 00 00 	movzwl 0x9c(%rbx),%eax
		list_add_tail(&new->list, &chan->srej_l);
    3140:	48 83 c7 08          	add    $0x8,%rdi
		new->tx_seq = chan->expected_tx_seq;
    3144:	66 89 47 f8          	mov    %ax,-0x8(%rdi)
	return (seq + 1) % (chan->tx_win_max + 1);
    3148:	0f b7 83 9c 00 00 00 	movzwl 0x9c(%rbx),%eax
    314f:	0f b7 4b 72          	movzwl 0x72(%rbx),%ecx
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
    3153:	48 8b b3 10 03 00 00 	mov    0x310(%rbx),%rsi
    315a:	83 c0 01             	add    $0x1,%eax
    315d:	83 c1 01             	add    $0x1,%ecx
    3160:	99                   	cltd   
    3161:	f7 f9                	idiv   %ecx
    3163:	66 89 93 9c 00 00 00 	mov    %dx,0x9c(%rbx)
    316a:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    316e:	e8 00 00 00 00       	callq  3173 <l2cap_send_srejframe+0xe3>
	while (tx_seq != chan->expected_tx_seq) {
    3173:	0f b7 8b 9c 00 00 00 	movzwl 0x9c(%rbx),%ecx
    317a:	66 44 39 e1          	cmp    %r12w,%cx
    317e:	0f 84 3c 02 00 00    	je     33c0 <l2cap_send_srejframe+0x330>
    3184:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    318b:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
		control |= __set_reqseq(chan, chan->expected_tx_seq);
    3192:	44 0f b7 f1          	movzwl %cx,%r14d
    3196:	83 e0 10             	and    $0x10,%eax
		return (super << L2CAP_EXT_CTRL_SUPER_SHIFT) &
    3199:	48 83 f8 01          	cmp    $0x1,%rax
    319d:	19 c0                	sbb    %eax,%eax
    319f:	25 0c 00 fd ff       	and    $0xfffd000c,%eax
    31a4:	05 00 00 03 00       	add    $0x30000,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    31a9:	83 e2 10             	and    $0x10,%edx
    31ac:	0f 85 1e ff ff ff    	jne    30d0 <l2cap_send_srejframe+0x40>
		return (reqseq << L2CAP_CTRL_REQSEQ_SHIFT) & L2CAP_CTRL_REQSEQ;
    31b2:	41 c1 e6 08          	shl    $0x8,%r14d
    31b6:	41 81 e6 00 3f 00 00 	and    $0x3f00,%r14d
    31bd:	e9 16 ff ff ff       	jmpq   30d8 <l2cap_send_srejframe+0x48>
    31c2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    31c8:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
    31cf:	83 e2 10             	and    $0x10,%edx
		hlen = L2CAP_EXT_HDR_SIZE;
    31d2:	48 83 fa 01          	cmp    $0x1,%rdx
    31d6:	45 19 ed             	sbb    %r13d,%r13d
    31d9:	41 83 e5 fe          	and    $0xfffffffe,%r13d
    31dd:	41 83 c5 08          	add    $0x8,%r13d
		hlen += L2CAP_FCS_SIZE;
    31e1:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    31e5:	41 8d 55 02          	lea    0x2(%r13),%edx
    31e9:	44 0f 44 ea          	cmove  %edx,%r13d
		control |= __set_reqseq(chan, chan->expected_tx_seq);
    31ed:	41 09 c6             	or     %eax,%r14d
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    31f0:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 31f7 <l2cap_send_srejframe+0x167>
    31f7:	0f 85 07 02 00 00    	jne    3404 <l2cap_send_srejframe+0x374>
	count = min_t(unsigned int, conn->mtu, hlen);
    31fd:	45 8b 7f 20          	mov    0x20(%r15),%r15d
    3201:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    3208:	45 39 fd             	cmp    %r15d,%r13d
    320b:	45 0f 46 fd          	cmovbe %r13d,%r15d
	control |= __set_sframe(chan);
    320f:	41 83 ce 01          	or     $0x1,%r14d
	count = min_t(unsigned int, conn->mtu, hlen);
    3213:	44 89 7d c4          	mov    %r15d,-0x3c(%rbp)
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    3217:	f0 0f ba b3 88 00 00 	lock btrl $0x7,0x88(%rbx)
    321e:	00 07 
    3220:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_FBIT, &chan->conn_state))
    3222:	85 c0                	test   %eax,%eax
    3224:	74 19                	je     323f <l2cap_send_srejframe+0x1af>
		(addr[nr / BITS_PER_LONG])) != 0;
    3226:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    322d:	83 e0 10             	and    $0x10,%eax
		return L2CAP_EXT_CTRL_FINAL;
    3230:	48 83 f8 01          	cmp    $0x1,%rax
    3234:	19 c0                	sbb    %eax,%eax
    3236:	83 e0 7e             	and    $0x7e,%eax
    3239:	83 c0 02             	add    $0x2,%eax
		control |= __set_ctrl_final(chan);
    323c:	41 09 c6             	or     %eax,%r14d
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    323f:	f0 0f ba b3 88 00 00 	lock btrl $0x3,0x88(%rbx)
    3246:	00 03 
    3248:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_PBIT, &chan->conn_state))
    324a:	85 c0                	test   %eax,%eax
    324c:	74 1d                	je     326b <l2cap_send_srejframe+0x1db>
		(addr[nr / BITS_PER_LONG])) != 0;
    324e:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    3255:	83 e0 10             	and    $0x10,%eax
		return L2CAP_EXT_CTRL_POLL;
    3258:	48 83 f8 01          	cmp    $0x1,%rax
    325c:	19 c0                	sbb    %eax,%eax
    325e:	25 10 00 fc ff       	and    $0xfffc0010,%eax
    3263:	05 00 00 04 00       	add    $0x40000,%eax
		control |= __set_ctrl_poll(chan);
    3268:	41 09 c6             	or     %eax,%r14d
	if ((skb = alloc_skb(len + BT_SKB_RESERVE, how))) {
    326b:	8b 45 c4             	mov    -0x3c(%rbp),%eax
	return __alloc_skb(size, priority, 0, NUMA_NO_NODE);
    326e:	31 d2                	xor    %edx,%edx
    3270:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    3275:	be 20 00 00 00       	mov    $0x20,%esi
    327a:	8d 78 08             	lea    0x8(%rax),%edi
    327d:	e8 00 00 00 00       	callq  3282 <l2cap_send_srejframe+0x1f2>
    3282:	48 85 c0             	test   %rax,%rax
    3285:	49 89 c7             	mov    %rax,%r15
    3288:	0f 84 80 fe ff ff    	je     310e <l2cap_send_srejframe+0x7e>
	skb->data += len;
    328e:	48 83 80 e0 00 00 00 	addq   $0x8,0xe0(%rax)
    3295:	08 
	skb->tail += len;
    3296:	83 80 cc 00 00 00 08 	addl   $0x8,0xcc(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    329d:	be 04 00 00 00       	mov    $0x4,%esi
    32a2:	48 89 c7             	mov    %rax,%rdi
		bt_cb(skb)->incoming  = 0;
    32a5:	c6 40 29 00          	movb   $0x0,0x29(%rax)
    32a9:	e8 00 00 00 00       	callq  32ae <l2cap_send_srejframe+0x21e>
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    32ae:	45 8d 45 fc          	lea    -0x4(%r13),%r8d
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    32b2:	49 89 c1             	mov    %rax,%r9
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    32b5:	4c 89 ff             	mov    %r15,%rdi
	lh->cid = cpu_to_le16(chan->dcid);
    32b8:	4c 89 4d b8          	mov    %r9,-0x48(%rbp)
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    32bc:	66 44 89 00          	mov    %r8w,(%rax)
	lh->cid = cpu_to_le16(chan->dcid);
    32c0:	0f b7 43 1a          	movzwl 0x1a(%rbx),%eax
    32c4:	66 41 89 41 02       	mov    %ax,0x2(%r9)
    32c9:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
    32d0:	83 e2 10             	and    $0x10,%edx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    32d3:	48 83 fa 01          	cmp    $0x1,%rdx
    32d7:	19 f6                	sbb    %esi,%esi
    32d9:	83 e6 fe             	and    $0xfffffffe,%esi
    32dc:	83 c6 04             	add    $0x4,%esi
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    32df:	e8 00 00 00 00       	callq  32e4 <l2cap_send_srejframe+0x254>
    32e4:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    32eb:	4c 8b 4d b8          	mov    -0x48(%rbp),%r9
    32ef:	83 e2 10             	and    $0x10,%edx
    32f2:	74 7c                	je     3370 <l2cap_send_srejframe+0x2e0>
	*((__le32 *)p) = cpu_to_le32(val);
    32f4:	44 89 30             	mov    %r14d,(%rax)
	if (chan->fcs == L2CAP_FCS_CRC16) {
    32f7:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    32fb:	74 7d                	je     337a <l2cap_send_srejframe+0x2ea>
	l2cap_do_send(chan, skb);
    32fd:	48 89 df             	mov    %rbx,%rdi
	skb->priority = HCI_PRIO_MAX;
    3300:	41 c7 47 78 07 00 00 	movl   $0x7,0x78(%r15)
    3307:	00 
	l2cap_do_send(chan, skb);
    3308:	4c 89 fe             	mov    %r15,%rsi
    330b:	e8 f0 d1 ff ff       	callq  500 <l2cap_do_send>
	return kmalloc_caches[index];
    3310:	48 8b 3d 00 00 00 00 	mov    0x0(%rip),%rdi        # 3317 <l2cap_send_srejframe+0x287>
			if (!s)
    3317:	48 85 ff             	test   %rdi,%rdi
    331a:	0f 85 fe fd ff ff    	jne    311e <l2cap_send_srejframe+0x8e>
				return ZERO_SIZE_PTR;
    3320:	bf 10 00 00 00       	mov    $0x10,%edi
    3325:	e9 0f fe ff ff       	jmpq   3139 <l2cap_send_srejframe+0xa9>
    332a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
	if (seq_list->tail == L2CAP_SEQ_LIST_CLEAR)
    3330:	44 0f b7 8b ea 02 00 	movzwl 0x2ea(%rbx),%r9d
    3337:	00 
    3338:	66 41 83 f9 ff       	cmp    $0xffff,%r9w
    333d:	74 71                	je     33b0 <l2cap_send_srejframe+0x320>
		seq_list->list[seq_list->tail & mask] = seq;
    333f:	45 21 c8             	and    %r9d,%r8d
    3342:	48 89 f2             	mov    %rsi,%rdx
    3345:	45 0f b7 c0          	movzwl %r8w,%r8d
    3349:	66 42 89 0c 47       	mov    %cx,(%rdi,%r8,2)
    334e:	48 03 93 f0 02 00 00 	add    0x2f0(%rbx),%rdx
	seq_list->tail = seq;
    3355:	66 89 8b ea 02 00 00 	mov    %cx,0x2ea(%rbx)
	seq_list->list[seq & mask] = L2CAP_SEQ_LIST_TAIL;
    335c:	b9 00 80 ff ff       	mov    $0xffff8000,%ecx
    3361:	66 89 0a             	mov    %cx,(%rdx)
    3364:	e9 97 fd ff ff       	jmpq   3100 <l2cap_send_srejframe+0x70>
    3369:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    3370:	66 44 89 30          	mov    %r14w,(%rax)
	if (chan->fcs == L2CAP_FCS_CRC16) {
    3374:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    3378:	75 83                	jne    32fd <l2cap_send_srejframe+0x26d>
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    337a:	8b 55 c4             	mov    -0x3c(%rbp),%edx
    337d:	4c 89 ce             	mov    %r9,%rsi
    3380:	31 ff                	xor    %edi,%edi
    3382:	83 ea 02             	sub    $0x2,%edx
    3385:	48 63 d2             	movslq %edx,%rdx
    3388:	e8 00 00 00 00       	callq  338d <l2cap_send_srejframe+0x2fd>
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    338d:	be 02 00 00 00       	mov    $0x2,%esi
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    3392:	41 89 c6             	mov    %eax,%r14d
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    3395:	4c 89 ff             	mov    %r15,%rdi
    3398:	e8 00 00 00 00       	callq  339d <l2cap_send_srejframe+0x30d>
	*((__le16 *)p) = cpu_to_le16(val);
    339d:	66 44 89 30          	mov    %r14w,(%rax)
    33a1:	e9 57 ff ff ff       	jmpq   32fd <l2cap_send_srejframe+0x26d>
    33a6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    33ad:	00 00 00 
		seq_list->head = seq;
    33b0:	66 89 8b e8 02 00 00 	mov    %cx,0x2e8(%rbx)
    33b7:	eb 9c                	jmp    3355 <l2cap_send_srejframe+0x2c5>
    33b9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
	return (seq + 1) % (chan->tx_win_max + 1);
    33c0:	0f b7 73 72          	movzwl 0x72(%rbx),%esi
    33c4:	0f b7 c1             	movzwl %cx,%eax
    33c7:	83 c0 01             	add    $0x1,%eax
    33ca:	99                   	cltd   
    33cb:	83 c6 01             	add    $0x1,%esi
    33ce:	f7 fe                	idiv   %esi
	return 0;
    33d0:	31 c0                	xor    %eax,%eax
    33d2:	66 89 93 9c 00 00 00 	mov    %dx,0x9c(%rbx)
}
    33d9:	48 83 c4 28          	add    $0x28,%rsp
    33dd:	5b                   	pop    %rbx
    33de:	41 5c                	pop    %r12
    33e0:	41 5d                	pop    %r13
    33e2:	41 5e                	pop    %r14
    33e4:	41 5f                	pop    %r15
    33e6:	5d                   	pop    %rbp
    33e7:	c3                   	retq   
    33e8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    33ef:	00 
    33f0:	48 83 c4 28          	add    $0x28,%rsp
			return -ENOMEM;
    33f4:	b8 f4 ff ff ff       	mov    $0xfffffff4,%eax
}
    33f9:	5b                   	pop    %rbx
    33fa:	41 5c                	pop    %r12
    33fc:	41 5d                	pop    %r13
    33fe:	41 5e                	pop    %r14
    3400:	41 5f                	pop    %r15
    3402:	5d                   	pop    %rbp
    3403:	c3                   	retq   
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    3404:	44 89 f1             	mov    %r14d,%ecx
    3407:	48 89 da             	mov    %rbx,%rdx
    340a:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    3411:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    3418:	31 c0                	xor    %eax,%eax
    341a:	e8 00 00 00 00       	callq  341f <l2cap_send_srejframe+0x38f>
    341f:	e9 d9 fd ff ff       	jmpq   31fd <l2cap_send_srejframe+0x16d>
    3424:	66 90                	xchg   %ax,%ax
    3426:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    342d:	00 00 00 

0000000000003430 <l2cap_retrans_timeout>:
{
    3430:	55                   	push   %rbp
    3431:	48 89 e5             	mov    %rsp,%rbp
    3434:	41 57                	push   %r15
    3436:	41 56                	push   %r14
    3438:	41 55                	push   %r13
    343a:	41 54                	push   %r12
    343c:	53                   	push   %rbx
    343d:	48 83 ec 28          	sub    $0x28,%rsp
    3441:	e8 00 00 00 00       	callq  3446 <l2cap_retrans_timeout+0x16>
	BT_DBG("chan %p", chan);
    3446:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 344d <l2cap_retrans_timeout+0x1d>
{
    344d:	49 89 fc             	mov    %rdi,%r12
	struct l2cap_chan *chan = container_of(work, struct l2cap_chan,
    3450:	4c 8d af a0 fe ff ff 	lea    -0x160(%rdi),%r13
	BT_DBG("chan %p", chan);
    3457:	0f 85 44 03 00 00    	jne    37a1 <l2cap_retrans_timeout+0x371>
	mutex_lock(&chan->lock);
    345d:	49 8d 84 24 e8 01 00 	lea    0x1e8(%r12),%rax
    3464:	00 
	__set_monitor_timer(chan);
    3465:	4d 8d 7c 24 70       	lea    0x70(%r12),%r15
    346a:	48 89 c7             	mov    %rax,%rdi
    346d:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    3471:	e8 00 00 00 00       	callq  3476 <l2cap_retrans_timeout+0x46>
	chan->retry_count = 1;
    3476:	41 c6 84 24 4a ff ff 	movb   $0x1,-0xb6(%r12)
    347d:	ff 01 
	__set_monitor_timer(chan);
    347f:	bf e0 2e 00 00       	mov    $0x2ee0,%edi
    3484:	e8 00 00 00 00       	callq  3489 <l2cap_retrans_timeout+0x59>
	BT_DBG("chan %p state %s timeout %ld", chan,
    3489:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 3490 <l2cap_retrans_timeout+0x60>
    3490:	49 89 c6             	mov    %rax,%r14
    3493:	0f 85 c8 02 00 00    	jne    3761 <l2cap_retrans_timeout+0x331>
	ret = del_timer_sync(&work->timer);
    3499:	49 8d bc 24 90 00 00 	lea    0x90(%r12),%rdi
    34a0:	00 
    34a1:	e8 00 00 00 00       	callq  34a6 <l2cap_retrans_timeout+0x76>
	if (ret)
    34a6:	85 c0                	test   %eax,%eax
    34a8:	0f 84 d2 00 00 00    	je     3580 <l2cap_retrans_timeout+0x150>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    34ae:	f0 41 80 64 24 70 fe 	lock andb $0xfe,0x70(%r12)
    34b5:	49 8d 5d 14          	lea    0x14(%r13),%rbx
	schedule_delayed_work(work, timeout);
    34b9:	4c 89 f6             	mov    %r14,%rsi
    34bc:	4c 89 ff             	mov    %r15,%rdi
    34bf:	e8 00 00 00 00       	callq  34c4 <l2cap_retrans_timeout+0x94>
		asm volatile(LOCK_PREFIX "orb %1,%0"
    34c4:	f0 41 80 8c 24 28 ff 	lock orb $0x2,-0xd8(%r12)
    34cb:	ff ff 02 
		(addr[nr / BITS_PER_LONG])) != 0;
    34ce:	49 8b 84 24 28 ff ff 	mov    -0xd8(%r12),%rax
    34d5:	ff 
	if (test_bit(CONN_LOCAL_BUSY, &chan->conn_state)) {
    34d6:	a8 20                	test   $0x20,%al
    34d8:	49 8b 84 24 30 ff ff 	mov    -0xd0(%r12),%rax
    34df:	ff 
    34e0:	0f 84 92 00 00 00    	je     3578 <l2cap_retrans_timeout+0x148>
    34e6:	48 c1 e8 04          	shr    $0x4,%rax
    34ea:	83 e0 01             	and    $0x1,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    34ed:	48 83 f8 01          	cmp    $0x1,%rax
    34f1:	45 19 f6             	sbb    %r14d,%r14d
    34f4:	41 81 e6 08 00 fe ff 	and    $0xfffe0008,%r14d
    34fb:	41 81 c6 10 00 02 00 	add    $0x20010,%r14d
		asm volatile(LOCK_PREFIX "orb %1,%0"
    3502:	f0 41 80 8c 24 29 ff 	lock orb $0x1,-0xd7(%r12)
    3509:	ff ff 01 
	control |= __set_reqseq(chan, chan->buffer_seq);
    350c:	41 0f b7 94 24 3e ff 	movzwl -0xc2(%r12),%edx
    3513:	ff ff 
		(addr[nr / BITS_PER_LONG])) != 0;
    3515:	49 8b 8c 24 30 ff ff 	mov    -0xd0(%r12),%rcx
    351c:	ff 
		return (reqseq << L2CAP_CTRL_REQSEQ_SHIFT) & L2CAP_CTRL_REQSEQ;
    351d:	89 d0                	mov    %edx,%eax
    351f:	c1 e0 08             	shl    $0x8,%eax
    3522:	25 00 3f 00 00       	and    $0x3f00,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    3527:	83 e1 10             	and    $0x10,%ecx
    352a:	74 0a                	je     3536 <l2cap_retrans_timeout+0x106>
		return (reqseq << L2CAP_EXT_CTRL_REQSEQ_SHIFT) &
    352c:	8d 04 95 00 00 00 00 	lea    0x0(,%rdx,4),%eax
    3533:	0f b7 c0             	movzwl %ax,%eax
	if (chan->state != BT_CONNECTED)
    3536:	41 80 bc 24 b0 fe ff 	cmpb   $0x1,-0x150(%r12)
    353d:	ff 01 
	struct l2cap_conn *conn = chan->conn;
    353f:	4d 8b bc 24 a8 fe ff 	mov    -0x158(%r12),%r15
    3546:	ff 
	if (chan->state != BT_CONNECTED)
    3547:	74 4f                	je     3598 <l2cap_retrans_timeout+0x168>
	mutex_unlock(&chan->lock);
    3549:	48 8b 7d c8          	mov    -0x38(%rbp),%rdi
    354d:	e8 00 00 00 00       	callq  3552 <l2cap_retrans_timeout+0x122>
    3552:	f0 ff 0b             	lock decl (%rbx)
    3555:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    3558:	84 c0                	test   %al,%al
    355a:	74 08                	je     3564 <l2cap_retrans_timeout+0x134>
		kfree(c);
    355c:	4c 89 ef             	mov    %r13,%rdi
    355f:	e8 00 00 00 00       	callq  3564 <l2cap_retrans_timeout+0x134>
}
    3564:	48 83 c4 28          	add    $0x28,%rsp
    3568:	5b                   	pop    %rbx
    3569:	41 5c                	pop    %r12
    356b:	41 5d                	pop    %r13
    356d:	41 5e                	pop    %r14
    356f:	41 5f                	pop    %r15
    3571:	5d                   	pop    %rbp
    3572:	c3                   	retq   
    3573:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		control |= __set_ctrl_super(chan, L2CAP_SUPER_RR);
    3578:	41 be 10 00 00 00    	mov    $0x10,%r14d
    357e:	eb 8c                	jmp    350c <l2cap_retrans_timeout+0xdc>
	atomic_inc(&c->refcnt);
    3580:	49 8d 5d 14          	lea    0x14(%r13),%rbx
	asm volatile(LOCK_PREFIX "incl %0"
    3584:	f0 41 ff 84 24 b4 fe 	lock incl -0x14c(%r12)
    358b:	ff ff 
    358d:	e9 27 ff ff ff       	jmpq   34b9 <l2cap_retrans_timeout+0x89>
    3592:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    3598:	49 8b 94 24 30 ff ff 	mov    -0xd0(%r12),%rdx
    359f:	ff 
    35a0:	48 c1 ea 04          	shr    $0x4,%rdx
    35a4:	83 e2 01             	and    $0x1,%edx
		hlen = L2CAP_EXT_HDR_SIZE;
    35a7:	48 83 fa 01          	cmp    $0x1,%rdx
    35ab:	45 19 c0             	sbb    %r8d,%r8d
    35ae:	41 83 e0 fe          	and    $0xfffffffe,%r8d
    35b2:	41 83 c0 08          	add    $0x8,%r8d
		hlen += L2CAP_FCS_SIZE;
    35b6:	41 80 bc 24 0f ff ff 	cmpb   $0x1,-0xf1(%r12)
    35bd:	ff 01 
    35bf:	41 8d 50 02          	lea    0x2(%r8),%edx
    35c3:	44 0f 44 c2          	cmove  %edx,%r8d
	control |= __set_reqseq(chan, chan->buffer_seq);
    35c7:	41 09 c6             	or     %eax,%r14d
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    35ca:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 35d1 <l2cap_retrans_timeout+0x1a1>
    35d1:	0f 85 e7 01 00 00    	jne    37be <l2cap_retrans_timeout+0x38e>
	count = min_t(unsigned int, conn->mtu, hlen);
    35d7:	45 8b 7f 20          	mov    0x20(%r15),%r15d
    35db:	49 8b 84 24 30 ff ff 	mov    -0xd0(%r12),%rax
    35e2:	ff 
    35e3:	45 39 f8             	cmp    %r15d,%r8d
    35e6:	45 0f 46 f8          	cmovbe %r8d,%r15d
	control |= __set_sframe(chan);
    35ea:	41 83 ce 01          	or     $0x1,%r14d
	count = min_t(unsigned int, conn->mtu, hlen);
    35ee:	44 89 7d c4          	mov    %r15d,-0x3c(%rbp)
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    35f2:	f0 41 0f ba b4 24 28 	lock btrl $0x7,-0xd8(%r12)
    35f9:	ff ff ff 07 
    35fd:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_FBIT, &chan->conn_state))
    35ff:	85 c0                	test   %eax,%eax
    3601:	74 1e                	je     3621 <l2cap_retrans_timeout+0x1f1>
		(addr[nr / BITS_PER_LONG])) != 0;
    3603:	49 8b 84 24 30 ff ff 	mov    -0xd0(%r12),%rax
    360a:	ff 
    360b:	48 c1 e8 04          	shr    $0x4,%rax
    360f:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_FINAL;
    3612:	48 83 f8 01          	cmp    $0x1,%rax
    3616:	19 c0                	sbb    %eax,%eax
    3618:	83 e0 7e             	and    $0x7e,%eax
    361b:	83 c0 02             	add    $0x2,%eax
		control |= __set_ctrl_final(chan);
    361e:	41 09 c6             	or     %eax,%r14d
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    3621:	f0 41 0f ba b4 24 28 	lock btrl $0x3,-0xd8(%r12)
    3628:	ff ff ff 03 
    362c:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_PBIT, &chan->conn_state))
    362e:	85 c0                	test   %eax,%eax
    3630:	0f 85 ca 00 00 00    	jne    3700 <l2cap_retrans_timeout+0x2d0>
	if ((skb = alloc_skb(len + BT_SKB_RESERVE, how))) {
    3636:	8b 45 c4             	mov    -0x3c(%rbp),%eax
	return __alloc_skb(size, priority, 0, NUMA_NO_NODE);
    3639:	31 d2                	xor    %edx,%edx
    363b:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    3640:	be 20 00 00 00       	mov    $0x20,%esi
    3645:	44 89 45 b8          	mov    %r8d,-0x48(%rbp)
    3649:	8d 78 08             	lea    0x8(%rax),%edi
    364c:	e8 00 00 00 00       	callq  3651 <l2cap_retrans_timeout+0x221>
    3651:	48 85 c0             	test   %rax,%rax
    3654:	49 89 c7             	mov    %rax,%r15
    3657:	0f 84 ec fe ff ff    	je     3549 <l2cap_retrans_timeout+0x119>
	skb->data += len;
    365d:	48 83 80 e0 00 00 00 	addq   $0x8,0xe0(%rax)
    3664:	08 
	skb->tail += len;
    3665:	83 80 cc 00 00 00 08 	addl   $0x8,0xcc(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    366c:	be 04 00 00 00       	mov    $0x4,%esi
    3671:	48 89 c7             	mov    %rax,%rdi
		bt_cb(skb)->incoming  = 0;
    3674:	c6 40 29 00          	movb   $0x0,0x29(%rax)
    3678:	e8 00 00 00 00       	callq  367d <l2cap_retrans_timeout+0x24d>
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    367d:	44 8b 45 b8          	mov    -0x48(%rbp),%r8d
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    3681:	49 89 c2             	mov    %rax,%r10
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    3684:	4c 89 ff             	mov    %r15,%rdi
	lh->cid = cpu_to_le16(chan->dcid);
    3687:	4c 89 55 b8          	mov    %r10,-0x48(%rbp)
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    368b:	41 83 e8 04          	sub    $0x4,%r8d
    368f:	66 44 89 00          	mov    %r8w,(%rax)
	lh->cid = cpu_to_le16(chan->dcid);
    3693:	41 0f b7 84 24 ba fe 	movzwl -0x146(%r12),%eax
    369a:	ff ff 
    369c:	66 41 89 42 02       	mov    %ax,0x2(%r10)
		(addr[nr / BITS_PER_LONG])) != 0;
    36a1:	49 8b 84 24 30 ff ff 	mov    -0xd0(%r12),%rax
    36a8:	ff 
    36a9:	48 c1 e8 04          	shr    $0x4,%rax
    36ad:	83 e0 01             	and    $0x1,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    36b0:	48 83 f8 01          	cmp    $0x1,%rax
    36b4:	19 f6                	sbb    %esi,%esi
    36b6:	83 e6 fe             	and    $0xfffffffe,%esi
    36b9:	83 c6 04             	add    $0x4,%esi
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    36bc:	e8 00 00 00 00       	callq  36c1 <l2cap_retrans_timeout+0x291>
    36c1:	49 8b 94 24 30 ff ff 	mov    -0xd0(%r12),%rdx
    36c8:	ff 
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    36c9:	4c 8b 55 b8          	mov    -0x48(%rbp),%r10
    36cd:	83 e2 10             	and    $0x10,%edx
    36d0:	75 5e                	jne    3730 <l2cap_retrans_timeout+0x300>
    36d2:	66 44 89 30          	mov    %r14w,(%rax)
	if (chan->fcs == L2CAP_FCS_CRC16) {
    36d6:	41 80 bc 24 0f ff ff 	cmpb   $0x1,-0xf1(%r12)
    36dd:	ff 01 
    36df:	74 57                	je     3738 <l2cap_retrans_timeout+0x308>
	skb->priority = HCI_PRIO_MAX;
    36e1:	41 c7 47 78 07 00 00 	movl   $0x7,0x78(%r15)
    36e8:	00 
	l2cap_do_send(chan, skb);
    36e9:	4c 89 fe             	mov    %r15,%rsi
    36ec:	4c 89 ef             	mov    %r13,%rdi
    36ef:	e8 0c ce ff ff       	callq  500 <l2cap_do_send>
    36f4:	e9 50 fe ff ff       	jmpq   3549 <l2cap_retrans_timeout+0x119>
    36f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    3700:	49 8b 84 24 30 ff ff 	mov    -0xd0(%r12),%rax
    3707:	ff 
    3708:	48 c1 e8 04          	shr    $0x4,%rax
    370c:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_POLL;
    370f:	48 83 f8 01          	cmp    $0x1,%rax
    3713:	19 c0                	sbb    %eax,%eax
    3715:	25 10 00 fc ff       	and    $0xfffc0010,%eax
    371a:	05 00 00 04 00       	add    $0x40000,%eax
		control |= __set_ctrl_poll(chan);
    371f:	41 09 c6             	or     %eax,%r14d
    3722:	e9 0f ff ff ff       	jmpq   3636 <l2cap_retrans_timeout+0x206>
    3727:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    372e:	00 00 
	*((__le32 *)p) = cpu_to_le32(val);
    3730:	44 89 30             	mov    %r14d,(%rax)
    3733:	eb a1                	jmp    36d6 <l2cap_retrans_timeout+0x2a6>
    3735:	0f 1f 00             	nopl   (%rax)
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    3738:	8b 55 c4             	mov    -0x3c(%rbp),%edx
    373b:	4c 89 d6             	mov    %r10,%rsi
    373e:	31 ff                	xor    %edi,%edi
    3740:	83 ea 02             	sub    $0x2,%edx
    3743:	48 63 d2             	movslq %edx,%rdx
    3746:	e8 00 00 00 00       	callq  374b <l2cap_retrans_timeout+0x31b>
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    374b:	be 02 00 00 00       	mov    $0x2,%esi
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    3750:	41 89 c6             	mov    %eax,%r14d
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    3753:	4c 89 ff             	mov    %r15,%rdi
    3756:	e8 00 00 00 00       	callq  375b <l2cap_retrans_timeout+0x32b>
	*((__le16 *)p) = cpu_to_le16(val);
    375b:	66 44 89 30          	mov    %r14w,(%rax)
    375f:	eb 80                	jmp    36e1 <l2cap_retrans_timeout+0x2b1>
	switch (state) {
    3761:	41 0f b6 84 24 b0 fe 	movzbl -0x150(%r12),%eax
    3768:	ff ff 
    376a:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    3771:	83 e8 01             	sub    $0x1,%eax
    3774:	83 f8 08             	cmp    $0x8,%eax
    3777:	77 08                	ja     3781 <l2cap_retrans_timeout+0x351>
    3779:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    3780:	00 
	BT_DBG("chan %p state %s timeout %ld", chan,
    3781:	4d 89 f0             	mov    %r14,%r8
    3784:	4c 89 ea             	mov    %r13,%rdx
    3787:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    378e:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    3795:	31 c0                	xor    %eax,%eax
    3797:	e8 00 00 00 00       	callq  379c <l2cap_retrans_timeout+0x36c>
    379c:	e9 f8 fc ff ff       	jmpq   3499 <l2cap_retrans_timeout+0x69>
	BT_DBG("chan %p", chan);
    37a1:	4c 89 ea             	mov    %r13,%rdx
    37a4:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    37ab:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    37b2:	31 c0                	xor    %eax,%eax
    37b4:	e8 00 00 00 00       	callq  37b9 <l2cap_retrans_timeout+0x389>
    37b9:	e9 9f fc ff ff       	jmpq   345d <l2cap_retrans_timeout+0x2d>
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    37be:	44 89 f1             	mov    %r14d,%ecx
    37c1:	4c 89 ea             	mov    %r13,%rdx
    37c4:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    37cb:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    37d2:	31 c0                	xor    %eax,%eax
    37d4:	44 89 45 c4          	mov    %r8d,-0x3c(%rbp)
    37d8:	e8 00 00 00 00       	callq  37dd <l2cap_retrans_timeout+0x3ad>
    37dd:	44 8b 45 c4          	mov    -0x3c(%rbp),%r8d
    37e1:	e9 f1 fd ff ff       	jmpq   35d7 <l2cap_retrans_timeout+0x1a7>
    37e6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    37ed:	00 00 00 

00000000000037f0 <l2cap_monitor_timeout>:
{
    37f0:	55                   	push   %rbp
    37f1:	48 89 e5             	mov    %rsp,%rbp
    37f4:	41 57                	push   %r15
    37f6:	41 56                	push   %r14
    37f8:	41 55                	push   %r13
    37fa:	41 54                	push   %r12
    37fc:	53                   	push   %rbx
    37fd:	48 83 ec 28          	sub    $0x28,%rsp
    3801:	e8 00 00 00 00       	callq  3806 <l2cap_monitor_timeout+0x16>
	BT_DBG("chan %p", chan);
    3806:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 380d <l2cap_monitor_timeout+0x1d>
{
    380d:	49 89 fd             	mov    %rdi,%r13
	struct l2cap_chan *chan = container_of(work, struct l2cap_chan,
    3810:	4c 8d a7 30 fe ff ff 	lea    -0x1d0(%rdi),%r12
	BT_DBG("chan %p", chan);
    3817:	0f 85 47 03 00 00    	jne    3b64 <l2cap_monitor_timeout+0x374>
	mutex_lock(&chan->lock);
    381d:	49 8d 9d 78 01 00 00 	lea    0x178(%r13),%rbx
    3824:	48 89 df             	mov    %rbx,%rdi
    3827:	e8 00 00 00 00       	callq  382c <l2cap_monitor_timeout+0x3c>
	if (chan->retry_count >= chan->remote_max_tx) {
    382c:	41 0f b6 85 da fe ff 	movzbl -0x126(%r13),%eax
    3833:	ff 
    3834:	41 3a 85 fa fe ff ff 	cmp    -0x106(%r13),%al
    383b:	0f 83 0f 01 00 00    	jae    3950 <l2cap_monitor_timeout+0x160>
	chan->retry_count++;
    3841:	83 c0 01             	add    $0x1,%eax
	__set_monitor_timer(chan);
    3844:	bf e0 2e 00 00       	mov    $0x2ee0,%edi
	chan->retry_count++;
    3849:	41 88 85 da fe ff ff 	mov    %al,-0x126(%r13)
	__set_monitor_timer(chan);
    3850:	e8 00 00 00 00       	callq  3855 <l2cap_monitor_timeout+0x65>
	BT_DBG("chan %p state %s timeout %ld", chan,
    3855:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 385c <l2cap_monitor_timeout+0x6c>
    385c:	49 89 c6             	mov    %rax,%r14
    385f:	0f 85 1c 03 00 00    	jne    3b81 <l2cap_monitor_timeout+0x391>
	ret = del_timer_sync(&work->timer);
    3865:	49 8d 7d 20          	lea    0x20(%r13),%rdi
    3869:	e8 00 00 00 00       	callq  386e <l2cap_monitor_timeout+0x7e>
	if (ret)
    386e:	85 c0                	test   %eax,%eax
    3870:	0f 84 ba 00 00 00    	je     3930 <l2cap_monitor_timeout+0x140>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    3876:	f0 41 80 65 00 fe    	lock andb $0xfe,0x0(%r13)
    387c:	49 8d 44 24 14       	lea    0x14(%r12),%rax
    3881:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
	schedule_delayed_work(work, timeout);
    3885:	4c 89 f6             	mov    %r14,%rsi
    3888:	4c 89 ef             	mov    %r13,%rdi
    388b:	e8 00 00 00 00       	callq  3890 <l2cap_monitor_timeout+0xa0>
		(addr[nr / BITS_PER_LONG])) != 0;
    3890:	49 8b 85 b8 fe ff ff 	mov    -0x148(%r13),%rax
	if (test_bit(CONN_LOCAL_BUSY, &chan->conn_state)) {
    3897:	a8 20                	test   $0x20,%al
    3899:	49 8b 85 c0 fe ff ff 	mov    -0x140(%r13),%rax
    38a0:	0f 84 f2 00 00 00    	je     3998 <l2cap_monitor_timeout+0x1a8>
    38a6:	48 c1 e8 04          	shr    $0x4,%rax
    38aa:	83 e0 01             	and    $0x1,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    38ad:	48 83 f8 01          	cmp    $0x1,%rax
    38b1:	45 19 f6             	sbb    %r14d,%r14d
    38b4:	41 81 e6 08 00 fe ff 	and    $0xfffe0008,%r14d
    38bb:	41 81 c6 10 00 02 00 	add    $0x20010,%r14d
		asm volatile(LOCK_PREFIX "orb %1,%0"
    38c2:	f0 41 80 8d b9 fe ff 	lock orb $0x1,-0x147(%r13)
    38c9:	ff 01 
	control |= __set_reqseq(chan, chan->buffer_seq);
    38cb:	41 0f b7 95 ce fe ff 	movzwl -0x132(%r13),%edx
    38d2:	ff 
		(addr[nr / BITS_PER_LONG])) != 0;
    38d3:	49 8b 8d c0 fe ff ff 	mov    -0x140(%r13),%rcx
		return (reqseq << L2CAP_CTRL_REQSEQ_SHIFT) & L2CAP_CTRL_REQSEQ;
    38da:	89 d0                	mov    %edx,%eax
    38dc:	c1 e0 08             	shl    $0x8,%eax
    38df:	25 00 3f 00 00       	and    $0x3f00,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    38e4:	83 e1 10             	and    $0x10,%ecx
    38e7:	74 0a                	je     38f3 <l2cap_monitor_timeout+0x103>
		return (reqseq << L2CAP_EXT_CTRL_REQSEQ_SHIFT) &
    38e9:	8d 04 95 00 00 00 00 	lea    0x0(,%rdx,4),%eax
    38f0:	0f b7 c0             	movzwl %ax,%eax
	if (chan->state != BT_CONNECTED)
    38f3:	41 80 bd 40 fe ff ff 	cmpb   $0x1,-0x1c0(%r13)
    38fa:	01 
	struct l2cap_conn *conn = chan->conn;
    38fb:	4d 8b bd 38 fe ff ff 	mov    -0x1c8(%r13),%r15
	if (chan->state != BT_CONNECTED)
    3902:	0f 84 a0 00 00 00    	je     39a8 <l2cap_monitor_timeout+0x1b8>
	mutex_unlock(&chan->lock);
    3908:	48 89 df             	mov    %rbx,%rdi
    390b:	e8 00 00 00 00       	callq  3910 <l2cap_monitor_timeout+0x120>
	asm volatile(LOCK_PREFIX "decl %0; sete %1"
    3910:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    3914:	f0 ff 08             	lock decl (%rax)
    3917:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    391a:	84 c0                	test   %al,%al
    391c:	75 5d                	jne    397b <l2cap_monitor_timeout+0x18b>
}
    391e:	48 83 c4 28          	add    $0x28,%rsp
    3922:	5b                   	pop    %rbx
    3923:	41 5c                	pop    %r12
    3925:	41 5d                	pop    %r13
    3927:	41 5e                	pop    %r14
    3929:	41 5f                	pop    %r15
    392b:	5d                   	pop    %rbp
    392c:	c3                   	retq   
    392d:	0f 1f 00             	nopl   (%rax)
	atomic_inc(&c->refcnt);
    3930:	49 8d 44 24 14       	lea    0x14(%r12),%rax
    3935:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
	asm volatile(LOCK_PREFIX "incl %0"
    3939:	f0 41 ff 85 44 fe ff 	lock incl -0x1bc(%r13)
    3940:	ff 
    3941:	e9 3f ff ff ff       	jmpq   3885 <l2cap_monitor_timeout+0x95>
    3946:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    394d:	00 00 00 
		l2cap_send_disconn_req(chan->conn, chan, ECONNABORTED);
    3950:	49 8b bd 38 fe ff ff 	mov    -0x1c8(%r13),%rdi
    3957:	ba 67 00 00 00       	mov    $0x67,%edx
    395c:	4c 89 e6             	mov    %r12,%rsi
    395f:	e8 9c ec ff ff       	callq  2600 <l2cap_send_disconn_req>
	mutex_unlock(&chan->lock);
    3964:	48 89 df             	mov    %rbx,%rdi
    3967:	e8 00 00 00 00       	callq  396c <l2cap_monitor_timeout+0x17c>
	asm volatile(LOCK_PREFIX "decl %0; sete %1"
    396c:	f0 41 ff 8d 44 fe ff 	lock decl -0x1bc(%r13)
    3973:	ff 
    3974:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    3977:	84 c0                	test   %al,%al
    3979:	74 a3                	je     391e <l2cap_monitor_timeout+0x12e>
		kfree(c);
    397b:	4c 89 e7             	mov    %r12,%rdi
    397e:	e8 00 00 00 00       	callq  3983 <l2cap_monitor_timeout+0x193>
}
    3983:	48 83 c4 28          	add    $0x28,%rsp
    3987:	5b                   	pop    %rbx
    3988:	41 5c                	pop    %r12
    398a:	41 5d                	pop    %r13
    398c:	41 5e                	pop    %r14
    398e:	41 5f                	pop    %r15
    3990:	5d                   	pop    %rbp
    3991:	c3                   	retq   
    3992:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		control |= __set_ctrl_super(chan, L2CAP_SUPER_RR);
    3998:	41 be 10 00 00 00    	mov    $0x10,%r14d
    399e:	e9 28 ff ff ff       	jmpq   38cb <l2cap_monitor_timeout+0xdb>
    39a3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    39a8:	49 8b 95 c0 fe ff ff 	mov    -0x140(%r13),%rdx
    39af:	48 c1 ea 04          	shr    $0x4,%rdx
    39b3:	83 e2 01             	and    $0x1,%edx
		hlen = L2CAP_EXT_HDR_SIZE;
    39b6:	48 83 fa 01          	cmp    $0x1,%rdx
    39ba:	45 19 c0             	sbb    %r8d,%r8d
    39bd:	41 83 e0 fe          	and    $0xfffffffe,%r8d
    39c1:	41 83 c0 08          	add    $0x8,%r8d
		hlen += L2CAP_FCS_SIZE;
    39c5:	41 80 bd 9f fe ff ff 	cmpb   $0x1,-0x161(%r13)
    39cc:	01 
    39cd:	41 8d 50 02          	lea    0x2(%r8),%edx
    39d1:	44 0f 44 c2          	cmove  %edx,%r8d
	control |= __set_reqseq(chan, chan->buffer_seq);
    39d5:	41 09 c6             	or     %eax,%r14d
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    39d8:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 39df <l2cap_monitor_timeout+0x1ef>
    39df:	0f 85 db 01 00 00    	jne    3bc0 <l2cap_monitor_timeout+0x3d0>
	count = min_t(unsigned int, conn->mtu, hlen);
    39e5:	45 8b 7f 20          	mov    0x20(%r15),%r15d
    39e9:	49 8b 85 c0 fe ff ff 	mov    -0x140(%r13),%rax
    39f0:	45 39 f8             	cmp    %r15d,%r8d
    39f3:	45 0f 46 f8          	cmovbe %r8d,%r15d
	control |= __set_sframe(chan);
    39f7:	41 83 ce 01          	or     $0x1,%r14d
	count = min_t(unsigned int, conn->mtu, hlen);
    39fb:	44 89 7d c4          	mov    %r15d,-0x3c(%rbp)
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    39ff:	f0 41 0f ba b5 b8 fe 	lock btrl $0x7,-0x148(%r13)
    3a06:	ff ff 07 
    3a09:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_FBIT, &chan->conn_state))
    3a0b:	85 c0                	test   %eax,%eax
    3a0d:	74 1d                	je     3a2c <l2cap_monitor_timeout+0x23c>
		(addr[nr / BITS_PER_LONG])) != 0;
    3a0f:	49 8b 85 c0 fe ff ff 	mov    -0x140(%r13),%rax
    3a16:	48 c1 e8 04          	shr    $0x4,%rax
    3a1a:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_FINAL;
    3a1d:	48 83 f8 01          	cmp    $0x1,%rax
    3a21:	19 c0                	sbb    %eax,%eax
    3a23:	83 e0 7e             	and    $0x7e,%eax
    3a26:	83 c0 02             	add    $0x2,%eax
		control |= __set_ctrl_final(chan);
    3a29:	41 09 c6             	or     %eax,%r14d
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    3a2c:	f0 41 0f ba b5 b8 fe 	lock btrl $0x3,-0x148(%r13)
    3a33:	ff ff 03 
    3a36:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_PBIT, &chan->conn_state))
    3a38:	85 c0                	test   %eax,%eax
    3a3a:	0f 85 c0 00 00 00    	jne    3b00 <l2cap_monitor_timeout+0x310>
	if ((skb = alloc_skb(len + BT_SKB_RESERVE, how))) {
    3a40:	8b 45 c4             	mov    -0x3c(%rbp),%eax
	return __alloc_skb(size, priority, 0, NUMA_NO_NODE);
    3a43:	31 d2                	xor    %edx,%edx
    3a45:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    3a4a:	be 20 00 00 00       	mov    $0x20,%esi
    3a4f:	44 89 45 b8          	mov    %r8d,-0x48(%rbp)
    3a53:	8d 78 08             	lea    0x8(%rax),%edi
    3a56:	e8 00 00 00 00       	callq  3a5b <l2cap_monitor_timeout+0x26b>
    3a5b:	48 85 c0             	test   %rax,%rax
    3a5e:	49 89 c7             	mov    %rax,%r15
    3a61:	0f 84 a1 fe ff ff    	je     3908 <l2cap_monitor_timeout+0x118>
	skb->data += len;
    3a67:	48 83 80 e0 00 00 00 	addq   $0x8,0xe0(%rax)
    3a6e:	08 
	skb->tail += len;
    3a6f:	83 80 cc 00 00 00 08 	addl   $0x8,0xcc(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    3a76:	be 04 00 00 00       	mov    $0x4,%esi
    3a7b:	48 89 c7             	mov    %rax,%rdi
		bt_cb(skb)->incoming  = 0;
    3a7e:	c6 40 29 00          	movb   $0x0,0x29(%rax)
    3a82:	e8 00 00 00 00       	callq  3a87 <l2cap_monitor_timeout+0x297>
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    3a87:	44 8b 45 b8          	mov    -0x48(%rbp),%r8d
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    3a8b:	49 89 c2             	mov    %rax,%r10
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    3a8e:	4c 89 ff             	mov    %r15,%rdi
	lh->cid = cpu_to_le16(chan->dcid);
    3a91:	4c 89 55 b8          	mov    %r10,-0x48(%rbp)
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    3a95:	41 83 e8 04          	sub    $0x4,%r8d
    3a99:	66 44 89 00          	mov    %r8w,(%rax)
	lh->cid = cpu_to_le16(chan->dcid);
    3a9d:	41 0f b7 85 4a fe ff 	movzwl -0x1b6(%r13),%eax
    3aa4:	ff 
    3aa5:	66 41 89 42 02       	mov    %ax,0x2(%r10)
		(addr[nr / BITS_PER_LONG])) != 0;
    3aaa:	49 8b 85 c0 fe ff ff 	mov    -0x140(%r13),%rax
    3ab1:	48 c1 e8 04          	shr    $0x4,%rax
    3ab5:	83 e0 01             	and    $0x1,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    3ab8:	48 83 f8 01          	cmp    $0x1,%rax
    3abc:	19 f6                	sbb    %esi,%esi
    3abe:	83 e6 fe             	and    $0xfffffffe,%esi
    3ac1:	83 c6 04             	add    $0x4,%esi
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    3ac4:	e8 00 00 00 00       	callq  3ac9 <l2cap_monitor_timeout+0x2d9>
    3ac9:	49 8b 95 c0 fe ff ff 	mov    -0x140(%r13),%rdx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    3ad0:	4c 8b 55 b8          	mov    -0x48(%rbp),%r10
    3ad4:	83 e2 10             	and    $0x10,%edx
    3ad7:	75 57                	jne    3b30 <l2cap_monitor_timeout+0x340>
    3ad9:	66 44 89 30          	mov    %r14w,(%rax)
	if (chan->fcs == L2CAP_FCS_CRC16) {
    3add:	41 80 bd 9f fe ff ff 	cmpb   $0x1,-0x161(%r13)
    3ae4:	01 
    3ae5:	74 51                	je     3b38 <l2cap_monitor_timeout+0x348>
	skb->priority = HCI_PRIO_MAX;
    3ae7:	41 c7 47 78 07 00 00 	movl   $0x7,0x78(%r15)
    3aee:	00 
	l2cap_do_send(chan, skb);
    3aef:	4c 89 fe             	mov    %r15,%rsi
    3af2:	4c 89 e7             	mov    %r12,%rdi
    3af5:	e8 06 ca ff ff       	callq  500 <l2cap_do_send>
    3afa:	e9 09 fe ff ff       	jmpq   3908 <l2cap_monitor_timeout+0x118>
    3aff:	90                   	nop
    3b00:	49 8b 85 c0 fe ff ff 	mov    -0x140(%r13),%rax
    3b07:	48 c1 e8 04          	shr    $0x4,%rax
    3b0b:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_POLL;
    3b0e:	48 83 f8 01          	cmp    $0x1,%rax
    3b12:	19 c0                	sbb    %eax,%eax
    3b14:	25 10 00 fc ff       	and    $0xfffc0010,%eax
    3b19:	05 00 00 04 00       	add    $0x40000,%eax
		control |= __set_ctrl_poll(chan);
    3b1e:	41 09 c6             	or     %eax,%r14d
    3b21:	e9 1a ff ff ff       	jmpq   3a40 <l2cap_monitor_timeout+0x250>
    3b26:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    3b2d:	00 00 00 
	*((__le32 *)p) = cpu_to_le32(val);
    3b30:	44 89 30             	mov    %r14d,(%rax)
    3b33:	eb a8                	jmp    3add <l2cap_monitor_timeout+0x2ed>
    3b35:	0f 1f 00             	nopl   (%rax)
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    3b38:	8b 55 c4             	mov    -0x3c(%rbp),%edx
    3b3b:	4c 89 d6             	mov    %r10,%rsi
    3b3e:	31 ff                	xor    %edi,%edi
    3b40:	83 ea 02             	sub    $0x2,%edx
    3b43:	48 63 d2             	movslq %edx,%rdx
    3b46:	e8 00 00 00 00       	callq  3b4b <l2cap_monitor_timeout+0x35b>
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    3b4b:	be 02 00 00 00       	mov    $0x2,%esi
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    3b50:	41 89 c6             	mov    %eax,%r14d
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    3b53:	4c 89 ff             	mov    %r15,%rdi
    3b56:	e8 00 00 00 00       	callq  3b5b <l2cap_monitor_timeout+0x36b>
	*((__le16 *)p) = cpu_to_le16(val);
    3b5b:	66 44 89 30          	mov    %r14w,(%rax)
    3b5f:	e9 83 ff ff ff       	jmpq   3ae7 <l2cap_monitor_timeout+0x2f7>
	BT_DBG("chan %p", chan);
    3b64:	4c 89 e2             	mov    %r12,%rdx
    3b67:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    3b6e:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    3b75:	31 c0                	xor    %eax,%eax
    3b77:	e8 00 00 00 00       	callq  3b7c <l2cap_monitor_timeout+0x38c>
    3b7c:	e9 9c fc ff ff       	jmpq   381d <l2cap_monitor_timeout+0x2d>
	switch (state) {
    3b81:	41 0f b6 85 40 fe ff 	movzbl -0x1c0(%r13),%eax
    3b88:	ff 
    3b89:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    3b90:	83 e8 01             	sub    $0x1,%eax
    3b93:	83 f8 08             	cmp    $0x8,%eax
    3b96:	77 08                	ja     3ba0 <l2cap_monitor_timeout+0x3b0>
    3b98:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    3b9f:	00 
	BT_DBG("chan %p state %s timeout %ld", chan,
    3ba0:	4d 89 f0             	mov    %r14,%r8
    3ba3:	4c 89 e2             	mov    %r12,%rdx
    3ba6:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    3bad:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    3bb4:	31 c0                	xor    %eax,%eax
    3bb6:	e8 00 00 00 00       	callq  3bbb <l2cap_monitor_timeout+0x3cb>
    3bbb:	e9 a5 fc ff ff       	jmpq   3865 <l2cap_monitor_timeout+0x75>
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    3bc0:	44 89 f1             	mov    %r14d,%ecx
    3bc3:	4c 89 e2             	mov    %r12,%rdx
    3bc6:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    3bcd:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    3bd4:	31 c0                	xor    %eax,%eax
    3bd6:	44 89 45 c4          	mov    %r8d,-0x3c(%rbp)
    3bda:	e8 00 00 00 00       	callq  3bdf <l2cap_monitor_timeout+0x3ef>
    3bdf:	44 8b 45 c4          	mov    -0x3c(%rbp),%r8d
    3be3:	e9 fd fd ff ff       	jmpq   39e5 <l2cap_monitor_timeout+0x1f5>
    3be8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    3bef:	00 

0000000000003bf0 <__l2cap_send_ack>:
{
    3bf0:	55                   	push   %rbp
    3bf1:	48 89 e5             	mov    %rsp,%rbp
    3bf4:	41 57                	push   %r15
    3bf6:	41 56                	push   %r14
    3bf8:	41 55                	push   %r13
    3bfa:	41 54                	push   %r12
    3bfc:	53                   	push   %rbx
    3bfd:	48 83 ec 18          	sub    $0x18,%rsp
    3c01:	e8 00 00 00 00       	callq  3c06 <__l2cap_send_ack+0x16>
    3c06:	48 8b 87 90 00 00 00 	mov    0x90(%rdi),%rax
	control |= __set_reqseq(chan, chan->buffer_seq);
    3c0d:	44 0f b7 af 9e 00 00 	movzwl 0x9e(%rdi),%r13d
    3c14:	00 
{
    3c15:	48 89 fb             	mov    %rdi,%rbx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    3c18:	a8 10                	test   $0x10,%al
    3c1a:	74 5c                	je     3c78 <__l2cap_send_ack+0x88>
    3c1c:	48 8b 83 88 00 00 00 	mov    0x88(%rbx),%rax
		return (reqseq << L2CAP_EXT_CTRL_REQSEQ_SHIFT) &
    3c23:	41 c1 e5 02          	shl    $0x2,%r13d
    3c27:	45 0f b7 ed          	movzwl %r13w,%r13d
	if (test_bit(CONN_LOCAL_BUSY, &chan->conn_state)) {
    3c2b:	a8 20                	test   $0x20,%al
    3c2d:	74 5f                	je     3c8e <__l2cap_send_ack+0x9e>
    3c2f:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    3c36:	48 c1 e8 04          	shr    $0x4,%rax
    3c3a:	83 e0 01             	and    $0x1,%eax
		return (super << L2CAP_EXT_CTRL_SUPER_SHIFT) &
    3c3d:	48 83 f8 01          	cmp    $0x1,%rax
    3c41:	19 c0                	sbb    %eax,%eax
    3c43:	25 08 00 fe ff       	and    $0xfffe0008,%eax
    3c48:	05 00 00 02 00       	add    $0x20000,%eax
		asm volatile(LOCK_PREFIX "orb %1,%0"
    3c4d:	f0 80 8b 89 00 00 00 	lock orb $0x1,0x89(%rbx)
    3c54:	01 
	if (chan->state != BT_CONNECTED)
    3c55:	80 7b 10 01          	cmpb   $0x1,0x10(%rbx)
	struct l2cap_conn *conn = chan->conn;
    3c59:	4c 8b 7b 08          	mov    0x8(%rbx),%r15
	if (chan->state != BT_CONNECTED)
    3c5d:	0f 84 ad 01 00 00    	je     3e10 <__l2cap_send_ack+0x220>
}
    3c63:	48 83 c4 18          	add    $0x18,%rsp
    3c67:	5b                   	pop    %rbx
    3c68:	41 5c                	pop    %r12
    3c6a:	41 5d                	pop    %r13
    3c6c:	41 5e                	pop    %r14
    3c6e:	41 5f                	pop    %r15
    3c70:	5d                   	pop    %rbp
    3c71:	c3                   	retq   
    3c72:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		(addr[nr / BITS_PER_LONG])) != 0;
    3c78:	48 8b 83 88 00 00 00 	mov    0x88(%rbx),%rax
		return (reqseq << L2CAP_CTRL_REQSEQ_SHIFT) & L2CAP_CTRL_REQSEQ;
    3c7f:	41 c1 e5 08          	shl    $0x8,%r13d
    3c83:	41 81 e5 00 3f 00 00 	and    $0x3f00,%r13d
	if (test_bit(CONN_LOCAL_BUSY, &chan->conn_state)) {
    3c8a:	a8 20                	test   $0x20,%al
    3c8c:	75 a1                	jne    3c2f <__l2cap_send_ack+0x3f>
	if (l2cap_ertm_send(chan) > 0)
    3c8e:	48 89 df             	mov    %rbx,%rdi
    3c91:	e8 ba ed ff ff       	callq  2a50 <l2cap_ertm_send>
    3c96:	85 c0                	test   %eax,%eax
    3c98:	7f c9                	jg     3c63 <__l2cap_send_ack+0x73>
	if (chan->state != BT_CONNECTED)
    3c9a:	80 7b 10 01          	cmpb   $0x1,0x10(%rbx)
    3c9e:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	struct l2cap_conn *conn = chan->conn;
    3ca5:	4c 8b 73 08          	mov    0x8(%rbx),%r14
	if (chan->state != BT_CONNECTED)
    3ca9:	75 b8                	jne    3c63 <__l2cap_send_ack+0x73>
    3cab:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    3cb2:	48 c1 e8 04          	shr    $0x4,%rax
    3cb6:	83 e0 01             	and    $0x1,%eax
		hlen = L2CAP_EXT_HDR_SIZE;
    3cb9:	48 83 f8 01          	cmp    $0x1,%rax
    3cbd:	45 19 e4             	sbb    %r12d,%r12d
    3cc0:	41 83 e4 fe          	and    $0xfffffffe,%r12d
    3cc4:	41 83 c4 08          	add    $0x8,%r12d
		hlen += L2CAP_FCS_SIZE;
    3cc8:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    3ccc:	41 8d 44 24 02       	lea    0x2(%r12),%eax
    3cd1:	44 0f 44 e0          	cmove  %eax,%r12d
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    3cd5:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 3cdc <__l2cap_send_ack+0xec>
    3cdc:	0f 85 33 03 00 00    	jne    4015 <__l2cap_send_ack+0x425>
	count = min_t(unsigned int, conn->mtu, hlen);
    3ce2:	45 8b 7e 20          	mov    0x20(%r14),%r15d
    3ce6:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    3ced:	45 39 fc             	cmp    %r15d,%r12d
    3cf0:	45 0f 46 fc          	cmovbe %r12d,%r15d
	control |= __set_sframe(chan);
    3cf4:	41 83 cd 01          	or     $0x1,%r13d
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    3cf8:	f0 0f ba b3 88 00 00 	lock btrl $0x7,0x88(%rbx)
    3cff:	00 07 
    3d01:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_FBIT, &chan->conn_state))
    3d03:	85 c0                	test   %eax,%eax
    3d05:	74 1d                	je     3d24 <__l2cap_send_ack+0x134>
		(addr[nr / BITS_PER_LONG])) != 0;
    3d07:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    3d0e:	48 c1 e8 04          	shr    $0x4,%rax
    3d12:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_FINAL;
    3d15:	48 83 f8 01          	cmp    $0x1,%rax
    3d19:	19 c0                	sbb    %eax,%eax
    3d1b:	83 e0 7e             	and    $0x7e,%eax
    3d1e:	83 c0 02             	add    $0x2,%eax
		control |= __set_ctrl_final(chan);
    3d21:	41 09 c5             	or     %eax,%r13d
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    3d24:	f0 0f ba b3 88 00 00 	lock btrl $0x3,0x88(%rbx)
    3d2b:	00 03 
    3d2d:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_PBIT, &chan->conn_state))
    3d2f:	85 c0                	test   %eax,%eax
    3d31:	74 21                	je     3d54 <__l2cap_send_ack+0x164>
		(addr[nr / BITS_PER_LONG])) != 0;
    3d33:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    3d3a:	48 c1 e8 04          	shr    $0x4,%rax
    3d3e:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_POLL;
    3d41:	48 83 f8 01          	cmp    $0x1,%rax
    3d45:	19 c0                	sbb    %eax,%eax
    3d47:	25 10 00 fc ff       	and    $0xfffc0010,%eax
    3d4c:	05 00 00 04 00       	add    $0x40000,%eax
		control |= __set_ctrl_poll(chan);
    3d51:	41 09 c5             	or     %eax,%r13d
	if ((skb = alloc_skb(len + BT_SKB_RESERVE, how))) {
    3d54:	41 8d 7f 08          	lea    0x8(%r15),%edi
	return __alloc_skb(size, priority, 0, NUMA_NO_NODE);
    3d58:	31 d2                	xor    %edx,%edx
    3d5a:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    3d5f:	be 20 00 00 00       	mov    $0x20,%esi
    3d64:	e8 00 00 00 00       	callq  3d69 <__l2cap_send_ack+0x179>
    3d69:	48 85 c0             	test   %rax,%rax
    3d6c:	49 89 c6             	mov    %rax,%r14
    3d6f:	0f 84 ee fe ff ff    	je     3c63 <__l2cap_send_ack+0x73>
	skb->data += len;
    3d75:	48 83 80 e0 00 00 00 	addq   $0x8,0xe0(%rax)
    3d7c:	08 
	skb->tail += len;
    3d7d:	83 80 cc 00 00 00 08 	addl   $0x8,0xcc(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    3d84:	be 04 00 00 00       	mov    $0x4,%esi
    3d89:	48 89 c7             	mov    %rax,%rdi
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    3d8c:	41 83 ec 04          	sub    $0x4,%r12d
		bt_cb(skb)->incoming  = 0;
    3d90:	c6 40 29 00          	movb   $0x0,0x29(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    3d94:	e8 00 00 00 00       	callq  3d99 <__l2cap_send_ack+0x1a9>
    3d99:	48 89 c1             	mov    %rax,%rcx
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    3d9c:	66 44 89 20          	mov    %r12w,(%rax)
	lh->cid = cpu_to_le16(chan->dcid);
    3da0:	0f b7 43 1a          	movzwl 0x1a(%rbx),%eax
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    3da4:	4c 89 f7             	mov    %r14,%rdi
	lh->cid = cpu_to_le16(chan->dcid);
    3da7:	48 89 4d c8          	mov    %rcx,-0x38(%rbp)
    3dab:	66 89 41 02          	mov    %ax,0x2(%rcx)
    3daf:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
    3db6:	48 c1 ea 04          	shr    $0x4,%rdx
    3dba:	83 e2 01             	and    $0x1,%edx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    3dbd:	48 83 fa 01          	cmp    $0x1,%rdx
    3dc1:	19 f6                	sbb    %esi,%esi
    3dc3:	83 e6 fe             	and    $0xfffffffe,%esi
    3dc6:	83 c6 04             	add    $0x4,%esi
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    3dc9:	e8 00 00 00 00       	callq  3dce <__l2cap_send_ack+0x1de>
    3dce:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    3dd5:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    3dd9:	83 e2 10             	and    $0x10,%edx
    3ddc:	0f 84 e0 01 00 00    	je     3fc2 <__l2cap_send_ack+0x3d2>
	*((__le32 *)p) = cpu_to_le32(val);
    3de2:	44 89 28             	mov    %r13d,(%rax)
	if (chan->fcs == L2CAP_FCS_CRC16) {
    3de5:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    3de9:	0f 84 dc 01 00 00    	je     3fcb <__l2cap_send_ack+0x3db>
	skb->priority = HCI_PRIO_MAX;
    3def:	41 c7 46 78 07 00 00 	movl   $0x7,0x78(%r14)
    3df6:	00 
	l2cap_do_send(chan, skb);
    3df7:	4c 89 f6             	mov    %r14,%rsi
    3dfa:	48 89 df             	mov    %rbx,%rdi
    3dfd:	e8 fe c6 ff ff       	callq  500 <l2cap_do_send>
    3e02:	e9 5c fe ff ff       	jmpq   3c63 <__l2cap_send_ack+0x73>
    3e07:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    3e0e:	00 00 
    3e10:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
    3e17:	48 c1 ea 04          	shr    $0x4,%rdx
    3e1b:	83 e2 01             	and    $0x1,%edx
		hlen = L2CAP_EXT_HDR_SIZE;
    3e1e:	48 83 fa 01          	cmp    $0x1,%rdx
    3e22:	45 19 e4             	sbb    %r12d,%r12d
    3e25:	41 83 e4 fe          	and    $0xfffffffe,%r12d
    3e29:	41 83 c4 08          	add    $0x8,%r12d
		hlen += L2CAP_FCS_SIZE;
    3e2d:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    3e31:	41 8d 54 24 02       	lea    0x2(%r12),%edx
    3e36:	44 0f 44 e2          	cmove  %edx,%r12d
		control |= __set_ctrl_super(chan, L2CAP_SUPER_RNR);
    3e3a:	41 09 c5             	or     %eax,%r13d
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    3e3d:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 3e44 <__l2cap_send_ack+0x254>
    3e44:	0f 85 ab 01 00 00    	jne    3ff5 <__l2cap_send_ack+0x405>
	count = min_t(unsigned int, conn->mtu, hlen);
    3e4a:	45 8b 7f 20          	mov    0x20(%r15),%r15d
	control |= __set_sframe(chan);
    3e4e:	45 89 ee             	mov    %r13d,%r14d
    3e51:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	count = min_t(unsigned int, conn->mtu, hlen);
    3e58:	45 39 fc             	cmp    %r15d,%r12d
    3e5b:	45 0f 46 fc          	cmovbe %r12d,%r15d
	control |= __set_sframe(chan);
    3e5f:	41 83 ce 01          	or     $0x1,%r14d
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    3e63:	f0 0f ba b3 88 00 00 	lock btrl $0x7,0x88(%rbx)
    3e6a:	00 07 
    3e6c:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_FBIT, &chan->conn_state))
    3e6e:	85 c0                	test   %eax,%eax
    3e70:	74 1d                	je     3e8f <__l2cap_send_ack+0x29f>
		(addr[nr / BITS_PER_LONG])) != 0;
    3e72:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    3e79:	48 c1 e8 04          	shr    $0x4,%rax
    3e7d:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_FINAL;
    3e80:	48 83 f8 01          	cmp    $0x1,%rax
    3e84:	19 c0                	sbb    %eax,%eax
    3e86:	83 e0 7e             	and    $0x7e,%eax
    3e89:	83 c0 02             	add    $0x2,%eax
		control |= __set_ctrl_final(chan);
    3e8c:	41 09 c6             	or     %eax,%r14d
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    3e8f:	f0 0f ba b3 88 00 00 	lock btrl $0x3,0x88(%rbx)
    3e96:	00 03 
    3e98:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_PBIT, &chan->conn_state))
    3e9a:	85 c0                	test   %eax,%eax
    3e9c:	0f 85 be 00 00 00    	jne    3f60 <__l2cap_send_ack+0x370>
	if ((skb = alloc_skb(len + BT_SKB_RESERVE, how))) {
    3ea2:	41 8d 7f 08          	lea    0x8(%r15),%edi
	return __alloc_skb(size, priority, 0, NUMA_NO_NODE);
    3ea6:	31 d2                	xor    %edx,%edx
    3ea8:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    3ead:	be 20 00 00 00       	mov    $0x20,%esi
    3eb2:	e8 00 00 00 00       	callq  3eb7 <__l2cap_send_ack+0x2c7>
    3eb7:	48 85 c0             	test   %rax,%rax
    3eba:	49 89 c5             	mov    %rax,%r13
    3ebd:	0f 84 a0 fd ff ff    	je     3c63 <__l2cap_send_ack+0x73>
	skb->data += len;
    3ec3:	48 83 80 e0 00 00 00 	addq   $0x8,0xe0(%rax)
    3eca:	08 
	skb->tail += len;
    3ecb:	83 80 cc 00 00 00 08 	addl   $0x8,0xcc(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    3ed2:	be 04 00 00 00       	mov    $0x4,%esi
    3ed7:	48 89 c7             	mov    %rax,%rdi
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    3eda:	41 83 ec 04          	sub    $0x4,%r12d
		bt_cb(skb)->incoming  = 0;
    3ede:	c6 40 29 00          	movb   $0x0,0x29(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    3ee2:	e8 00 00 00 00       	callq  3ee7 <__l2cap_send_ack+0x2f7>
    3ee7:	48 89 c1             	mov    %rax,%rcx
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    3eea:	66 44 89 20          	mov    %r12w,(%rax)
	lh->cid = cpu_to_le16(chan->dcid);
    3eee:	0f b7 43 1a          	movzwl 0x1a(%rbx),%eax
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    3ef2:	4c 89 ef             	mov    %r13,%rdi
	lh->cid = cpu_to_le16(chan->dcid);
    3ef5:	48 89 4d c8          	mov    %rcx,-0x38(%rbp)
    3ef9:	66 89 41 02          	mov    %ax,0x2(%rcx)
		(addr[nr / BITS_PER_LONG])) != 0;
    3efd:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
    3f04:	48 c1 ea 04          	shr    $0x4,%rdx
    3f08:	83 e2 01             	and    $0x1,%edx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    3f0b:	48 83 fa 01          	cmp    $0x1,%rdx
    3f0f:	19 f6                	sbb    %esi,%esi
    3f11:	83 e6 fe             	and    $0xfffffffe,%esi
    3f14:	83 c6 04             	add    $0x4,%esi
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    3f17:	e8 00 00 00 00       	callq  3f1c <__l2cap_send_ack+0x32c>
    3f1c:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    3f23:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    3f27:	83 e2 10             	and    $0x10,%edx
    3f2a:	75 64                	jne    3f90 <__l2cap_send_ack+0x3a0>
    3f2c:	66 44 89 30          	mov    %r14w,(%rax)
	if (chan->fcs == L2CAP_FCS_CRC16) {
    3f30:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    3f34:	74 62                	je     3f98 <__l2cap_send_ack+0x3a8>
	skb->priority = HCI_PRIO_MAX;
    3f36:	41 c7 45 78 07 00 00 	movl   $0x7,0x78(%r13)
    3f3d:	00 
	l2cap_do_send(chan, skb);
    3f3e:	4c 89 ee             	mov    %r13,%rsi
    3f41:	48 89 df             	mov    %rbx,%rdi
    3f44:	e8 b7 c5 ff ff       	callq  500 <l2cap_do_send>
}
    3f49:	48 83 c4 18          	add    $0x18,%rsp
    3f4d:	5b                   	pop    %rbx
    3f4e:	41 5c                	pop    %r12
    3f50:	41 5d                	pop    %r13
    3f52:	41 5e                	pop    %r14
    3f54:	41 5f                	pop    %r15
    3f56:	5d                   	pop    %rbp
    3f57:	c3                   	retq   
    3f58:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    3f5f:	00 
    3f60:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    3f67:	48 c1 e8 04          	shr    $0x4,%rax
    3f6b:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_POLL;
    3f6e:	48 83 f8 01          	cmp    $0x1,%rax
    3f72:	19 c0                	sbb    %eax,%eax
    3f74:	25 10 00 fc ff       	and    $0xfffc0010,%eax
    3f79:	05 00 00 04 00       	add    $0x40000,%eax
		control |= __set_ctrl_poll(chan);
    3f7e:	41 09 c6             	or     %eax,%r14d
    3f81:	e9 1c ff ff ff       	jmpq   3ea2 <__l2cap_send_ack+0x2b2>
    3f86:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    3f8d:	00 00 00 
    3f90:	44 89 30             	mov    %r14d,(%rax)
    3f93:	eb 9b                	jmp    3f30 <__l2cap_send_ack+0x340>
    3f95:	0f 1f 00             	nopl   (%rax)
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    3f98:	41 8d 57 fe          	lea    -0x2(%r15),%edx
    3f9c:	48 89 ce             	mov    %rcx,%rsi
    3f9f:	31 ff                	xor    %edi,%edi
    3fa1:	48 63 d2             	movslq %edx,%rdx
    3fa4:	e8 00 00 00 00       	callq  3fa9 <__l2cap_send_ack+0x3b9>
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    3fa9:	be 02 00 00 00       	mov    $0x2,%esi
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    3fae:	41 89 c4             	mov    %eax,%r12d
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    3fb1:	4c 89 ef             	mov    %r13,%rdi
    3fb4:	e8 00 00 00 00       	callq  3fb9 <__l2cap_send_ack+0x3c9>
	*((__le16 *)p) = cpu_to_le16(val);
    3fb9:	66 44 89 20          	mov    %r12w,(%rax)
    3fbd:	e9 74 ff ff ff       	jmpq   3f36 <__l2cap_send_ack+0x346>
    3fc2:	66 44 89 28          	mov    %r13w,(%rax)
    3fc6:	e9 1a fe ff ff       	jmpq   3de5 <__l2cap_send_ack+0x1f5>
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    3fcb:	41 8d 57 fe          	lea    -0x2(%r15),%edx
    3fcf:	48 89 ce             	mov    %rcx,%rsi
    3fd2:	31 ff                	xor    %edi,%edi
    3fd4:	48 63 d2             	movslq %edx,%rdx
    3fd7:	e8 00 00 00 00       	callq  3fdc <__l2cap_send_ack+0x3ec>
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    3fdc:	be 02 00 00 00       	mov    $0x2,%esi
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    3fe1:	41 89 c4             	mov    %eax,%r12d
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    3fe4:	4c 89 f7             	mov    %r14,%rdi
    3fe7:	e8 00 00 00 00       	callq  3fec <__l2cap_send_ack+0x3fc>
    3fec:	66 44 89 20          	mov    %r12w,(%rax)
    3ff0:	e9 fa fd ff ff       	jmpq   3def <__l2cap_send_ack+0x1ff>
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    3ff5:	44 89 e9             	mov    %r13d,%ecx
    3ff8:	48 89 da             	mov    %rbx,%rdx
    3ffb:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    4002:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    4009:	31 c0                	xor    %eax,%eax
    400b:	e8 00 00 00 00       	callq  4010 <__l2cap_send_ack+0x420>
    4010:	e9 35 fe ff ff       	jmpq   3e4a <__l2cap_send_ack+0x25a>
    4015:	44 89 e9             	mov    %r13d,%ecx
    4018:	48 89 da             	mov    %rbx,%rdx
    401b:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    4022:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    4029:	31 c0                	xor    %eax,%eax
    402b:	e8 00 00 00 00       	callq  4030 <__l2cap_send_ack+0x440>
    4030:	e9 ad fc ff ff       	jmpq   3ce2 <__l2cap_send_ack+0xf2>
    4035:	90                   	nop
    4036:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    403d:	00 00 00 

0000000000004040 <l2cap_ack_timeout>:
{
    4040:	55                   	push   %rbp
    4041:	48 89 e5             	mov    %rsp,%rbp
    4044:	41 55                	push   %r13
    4046:	41 54                	push   %r12
    4048:	53                   	push   %rbx
    4049:	48 83 ec 08          	sub    $0x8,%rsp
    404d:	e8 00 00 00 00       	callq  4052 <l2cap_ack_timeout+0x12>
	BT_DBG("chan %p", chan);
    4052:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 4059 <l2cap_ack_timeout+0x19>
{
    4059:	48 89 fb             	mov    %rdi,%rbx
	struct l2cap_chan *chan = container_of(work, struct l2cap_chan,
    405c:	4c 8d af c0 fd ff ff 	lea    -0x240(%rdi),%r13
	BT_DBG("chan %p", chan);
    4063:	75 40                	jne    40a5 <l2cap_ack_timeout+0x65>
	mutex_lock(&chan->lock);
    4065:	4c 8d a3 08 01 00 00 	lea    0x108(%rbx),%r12
    406c:	4c 89 e7             	mov    %r12,%rdi
    406f:	e8 00 00 00 00       	callq  4074 <l2cap_ack_timeout+0x34>
	__l2cap_send_ack(chan);
    4074:	4c 89 ef             	mov    %r13,%rdi
    4077:	e8 74 fb ff ff       	callq  3bf0 <__l2cap_send_ack>
	mutex_unlock(&chan->lock);
    407c:	4c 89 e7             	mov    %r12,%rdi
    407f:	e8 00 00 00 00       	callq  4084 <l2cap_ack_timeout+0x44>
    4084:	f0 ff 8b d4 fd ff ff 	lock decl -0x22c(%rbx)
    408b:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    408e:	84 c0                	test   %al,%al
    4090:	74 08                	je     409a <l2cap_ack_timeout+0x5a>
		kfree(c);
    4092:	4c 89 ef             	mov    %r13,%rdi
    4095:	e8 00 00 00 00       	callq  409a <l2cap_ack_timeout+0x5a>
}
    409a:	48 83 c4 08          	add    $0x8,%rsp
    409e:	5b                   	pop    %rbx
    409f:	41 5c                	pop    %r12
    40a1:	41 5d                	pop    %r13
    40a3:	5d                   	pop    %rbp
    40a4:	c3                   	retq   
	BT_DBG("chan %p", chan);
    40a5:	4c 89 ea             	mov    %r13,%rdx
    40a8:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    40af:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    40b6:	31 c0                	xor    %eax,%eax
    40b8:	e8 00 00 00 00       	callq  40bd <l2cap_ack_timeout+0x7d>
    40bd:	eb a6                	jmp    4065 <l2cap_ack_timeout+0x25>
    40bf:	90                   	nop

00000000000040c0 <l2cap_config_rsp>:
{
    40c0:	55                   	push   %rbp
    40c1:	48 89 e5             	mov    %rsp,%rbp
    40c4:	41 57                	push   %r15
    40c6:	49 89 d7             	mov    %rdx,%r15
    40c9:	41 56                	push   %r14
    40cb:	49 89 f6             	mov    %rsi,%r14
    40ce:	41 55                	push   %r13
    40d0:	41 54                	push   %r12
    40d2:	49 89 fc             	mov    %rdi,%r12
    40d5:	53                   	push   %rbx
    40d6:	48 83 ec 78          	sub    $0x78,%rsp
	int len = le16_to_cpu(cmd->len) - sizeof(*rsp);
    40da:	44 0f b7 6e 02       	movzwl 0x2(%rsi),%r13d
	result = __le16_to_cpu(rsp->result);
    40df:	44 0f b7 42 04       	movzwl 0x4(%rdx),%r8d
{
    40e4:	65 48 8b 04 25 28 00 	mov    %gs:0x28,%rax
    40eb:	00 00 
    40ed:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    40f1:	31 c0                	xor    %eax,%eax
	flags  = __le16_to_cpu(rsp->flags);
    40f3:	0f b7 42 02          	movzwl 0x2(%rdx),%eax
	scid   = __le16_to_cpu(rsp->scid);
    40f7:	0f b7 1a             	movzwl (%rdx),%ebx
	int len = le16_to_cpu(cmd->len) - sizeof(*rsp);
    40fa:	41 83 ed 06          	sub    $0x6,%r13d
	BT_DBG("scid 0x%4.4x flags 0x%2.2x result 0x%2.2x len %d", scid, flags,
    40fe:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 4105 <l2cap_config_rsp+0x45>
	result = __le16_to_cpu(rsp->result);
    4105:	66 44 89 45 86       	mov    %r8w,-0x7a(%rbp)
	int len = le16_to_cpu(cmd->len) - sizeof(*rsp);
    410a:	45 89 eb             	mov    %r13d,%r11d
	flags  = __le16_to_cpu(rsp->flags);
    410d:	66 89 85 76 ff ff ff 	mov    %ax,-0x8a(%rbp)
	BT_DBG("scid 0x%4.4x flags 0x%2.2x result 0x%2.2x len %d", scid, flags,
    4114:	0f 85 eb 05 00 00    	jne    4705 <l2cap_config_rsp+0x645>
	chan = l2cap_get_chan_by_scid(conn, scid);
    411a:	89 de                	mov    %ebx,%esi
    411c:	4c 89 e7             	mov    %r12,%rdi
    411f:	44 89 9d 78 ff ff ff 	mov    %r11d,-0x88(%rbp)
    4126:	e8 65 c0 ff ff       	callq  190 <l2cap_get_chan_by_scid>
	if (!chan)
    412b:	48 85 c0             	test   %rax,%rax
	chan = l2cap_get_chan_by_scid(conn, scid);
    412e:	48 89 c3             	mov    %rax,%rbx
	if (!chan)
    4131:	0f 84 f9 02 00 00    	je     4430 <l2cap_config_rsp+0x370>
	switch (result) {
    4137:	0f b7 45 86          	movzwl -0x7a(%rbp),%eax
    413b:	66 83 f8 01          	cmp    $0x1,%ax
    413f:	0f 84 eb 00 00 00    	je     4230 <l2cap_config_rsp+0x170>
    4145:	44 8b 9d 78 ff ff ff 	mov    -0x88(%rbp),%r11d
    414c:	72 5a                	jb     41a8 <l2cap_config_rsp+0xe8>
    414e:	66 83 f8 04          	cmp    $0x4,%ax
    4152:	0f 85 e2 00 00 00    	jne    423a <l2cap_config_rsp+0x17a>
		asm volatile(LOCK_PREFIX "orb %1,%0"
    4158:	f0 80 8b 81 00 00 00 	lock orb $0x4,0x81(%rbx)
    415f:	04 
		(addr[nr / BITS_PER_LONG])) != 0;
    4160:	48 8b 83 80 00 00 00 	mov    0x80(%rbx),%rax
		if (test_bit(CONF_LOC_CONF_PEND, &chan->conf_state)) {
    4167:	f6 c4 02             	test   $0x2,%ah
    416a:	0f 85 b0 01 00 00    	jne    4320 <l2cap_config_rsp+0x260>
	int err = 0;
    4170:	45 31 e4             	xor    %r12d,%r12d
	mutex_unlock(&chan->lock);
    4173:	48 8d bb 48 03 00 00 	lea    0x348(%rbx),%rdi
    417a:	e8 00 00 00 00       	callq  417f <l2cap_config_rsp+0xbf>
	return err;
    417f:	44 89 e0             	mov    %r12d,%eax
}
    4182:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    4186:	65 48 33 0c 25 28 00 	xor    %gs:0x28,%rcx
    418d:	00 00 
    418f:	0f 85 6b 05 00 00    	jne    4700 <l2cap_config_rsp+0x640>
    4195:	48 83 c4 78          	add    $0x78,%rsp
    4199:	5b                   	pop    %rbx
    419a:	41 5c                	pop    %r12
    419c:	41 5d                	pop    %r13
    419e:	41 5e                	pop    %r14
    41a0:	41 5f                	pop    %r15
    41a2:	5d                   	pop    %rbp
    41a3:	c3                   	retq   
    41a4:	0f 1f 40 00          	nopl   0x0(%rax)
    41a8:	49 83 c7 06          	add    $0x6,%r15
	BT_DBG("chan %p, rsp %p, len %d", chan, rsp, len);
    41ac:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 41b3 <l2cap_config_rsp+0xf3>
    41b3:	0f 85 c0 05 00 00    	jne    4779 <l2cap_config_rsp+0x6b9>
	if ((chan->mode != L2CAP_MODE_ERTM) && (chan->mode != L2CAP_MODE_STREAMING))
    41b9:	0f b6 43 24          	movzbl 0x24(%rbx),%eax
    41bd:	8d 50 fd             	lea    -0x3(%rax),%edx
    41c0:	80 fa 01             	cmp    $0x1,%dl
    41c3:	0f 86 b7 01 00 00    	jbe    4380 <l2cap_config_rsp+0x2c0>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    41c9:	f0 80 a3 81 00 00 00 	lock andb $0xfb,0x81(%rbx)
    41d0:	fb 
	if (flags & 0x01)
    41d1:	f6 85 76 ff ff ff 01 	testb  $0x1,-0x8a(%rbp)
    41d8:	75 96                	jne    4170 <l2cap_config_rsp+0xb0>
		asm volatile(LOCK_PREFIX "orb %1,%0"
    41da:	f0 80 8b 80 00 00 00 	lock orb $0x2,0x80(%rbx)
    41e1:	02 
		(addr[nr / BITS_PER_LONG])) != 0;
    41e2:	48 8b 83 80 00 00 00 	mov    0x80(%rbx),%rax
	if (test_bit(CONF_OUTPUT_DONE, &chan->conf_state)) {
    41e9:	a8 04                	test   $0x4,%al
    41eb:	74 83                	je     4170 <l2cap_config_rsp+0xb0>
	if (chan->mode != L2CAP_MODE_ERTM && chan->mode != L2CAP_MODE_STREAMING)
    41ed:	0f b6 43 24          	movzbl 0x24(%rbx),%eax
    41f1:	83 e8 03             	sub    $0x3,%eax
    41f4:	3c 01                	cmp    $0x1,%al
    41f6:	0f 86 ec 04 00 00    	jbe    46e8 <l2cap_config_rsp+0x628>
		chan->fcs = L2CAP_FCS_NONE;
    41fc:	c6 43 6f 00          	movb   $0x0,0x6f(%rbx)
		l2cap_state_change(chan, BT_CONNECTED);
    4200:	be 01 00 00 00       	mov    $0x1,%esi
    4205:	48 89 df             	mov    %rbx,%rdi
    4208:	e8 13 c5 ff ff       	callq  720 <l2cap_state_change>
		if (chan->mode == L2CAP_MODE_ERTM ||
    420d:	0f b6 43 24          	movzbl 0x24(%rbx),%eax
    4211:	8d 50 fd             	lea    -0x3(%rax),%edx
    4214:	80 fa 01             	cmp    $0x1,%dl
    4217:	0f 86 e9 02 00 00    	jbe    4506 <l2cap_config_rsp+0x446>
	int err = 0;
    421d:	45 31 e4             	xor    %r12d,%r12d
			l2cap_chan_ready(chan);
    4220:	48 89 df             	mov    %rbx,%rdi
    4223:	e8 38 e2 ff ff       	callq  2460 <l2cap_chan_ready>
    4228:	e9 46 ff ff ff       	jmpq   4173 <l2cap_config_rsp+0xb3>
    422d:	0f 1f 00             	nopl   (%rax)
		if (chan->num_conf_rsp <= L2CAP_CONF_MAX_CONF_RSP) {
    4230:	80 7b 6e 02          	cmpb   $0x2,0x6e(%rbx)
    4234:	0f 86 86 00 00 00    	jbe    42c0 <l2cap_config_rsp+0x200>
	struct sock *sk = chan->sk;
    423a:	4c 8b 2b             	mov    (%rbx),%r13
    423d:	31 f6                	xor    %esi,%esi
		__set_chan_timer(chan, L2CAP_DISC_REJ_TIMEOUT);
    423f:	4c 8d b3 f0 00 00 00 	lea    0xf0(%rbx),%r14
    4246:	4c 89 ef             	mov    %r13,%rdi
    4249:	e8 00 00 00 00       	callq  424e <l2cap_config_rsp+0x18e>
static inline void l2cap_chan_set_err(struct l2cap_chan *chan, int err)
    424e:	48 8b 03             	mov    (%rbx),%rax
	release_sock(sk);
    4251:	4c 89 ef             	mov    %r13,%rdi
	sk->sk_err = err;
    4254:	c7 80 7c 01 00 00 68 	movl   $0x68,0x17c(%rax)
    425b:	00 00 00 
	release_sock(sk);
    425e:	e8 00 00 00 00       	callq  4263 <l2cap_config_rsp+0x1a3>
		__set_chan_timer(chan, L2CAP_DISC_REJ_TIMEOUT);
    4263:	bf 88 13 00 00       	mov    $0x1388,%edi
    4268:	e8 00 00 00 00       	callq  426d <l2cap_config_rsp+0x1ad>
	BT_DBG("chan %p state %s timeout %ld", chan,
    426d:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 4274 <l2cap_config_rsp+0x1b4>
    4274:	49 89 c5             	mov    %rax,%r13
    4277:	0f 85 2d 05 00 00    	jne    47aa <l2cap_config_rsp+0x6ea>
	ret = del_timer_sync(&work->timer);
    427d:	48 8d bb 10 01 00 00 	lea    0x110(%rbx),%rdi
    4284:	e8 00 00 00 00       	callq  4289 <l2cap_config_rsp+0x1c9>
	if (ret)
    4289:	85 c0                	test   %eax,%eax
    428b:	0f 84 8f 01 00 00    	je     4420 <l2cap_config_rsp+0x360>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    4291:	f0 80 a3 f0 00 00 00 	lock andb $0xfe,0xf0(%rbx)
    4298:	fe 
	schedule_delayed_work(work, timeout);
    4299:	4c 89 ee             	mov    %r13,%rsi
    429c:	4c 89 f7             	mov    %r14,%rdi
    429f:	e8 00 00 00 00       	callq  42a4 <l2cap_config_rsp+0x1e4>
				l2cap_send_disconn_req(conn, chan, ECONNRESET);
    42a4:	ba 68 00 00 00       	mov    $0x68,%edx
    42a9:	48 89 de             	mov    %rbx,%rsi
    42ac:	4c 89 e7             	mov    %r12,%rdi
    42af:	e8 4c e3 ff ff       	callq  2600 <l2cap_send_disconn_req>
    42b4:	e9 b7 fe ff ff       	jmpq   4170 <l2cap_config_rsp+0xb0>
    42b9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
			if (len > sizeof(req) - sizeof(struct l2cap_conf_req)) {
    42c0:	41 83 fd 3c          	cmp    $0x3c,%r13d
    42c4:	77 de                	ja     42a4 <l2cap_config_rsp+0x1e4>
			len = l2cap_parse_conf_rsp(chan, rsp->data, len,
    42c6:	49 8d 77 06          	lea    0x6(%r15),%rsi
    42ca:	4c 8d 45 86          	lea    -0x7a(%rbp),%r8
    42ce:	48 8d 4d 88          	lea    -0x78(%rbp),%rcx
			result = L2CAP_CONF_SUCCESS;
    42d2:	45 31 f6             	xor    %r14d,%r14d
			len = l2cap_parse_conf_rsp(chan, rsp->data, len,
    42d5:	44 89 ea             	mov    %r13d,%edx
    42d8:	48 89 df             	mov    %rbx,%rdi
			result = L2CAP_CONF_SUCCESS;
    42db:	66 44 89 75 86       	mov    %r14w,-0x7a(%rbp)
			len = l2cap_parse_conf_rsp(chan, rsp->data, len,
    42e0:	e8 5b dd ff ff       	callq  2040 <l2cap_parse_conf_rsp>
			if (len < 0) {
    42e5:	85 c0                	test   %eax,%eax
			len = l2cap_parse_conf_rsp(chan, rsp->data, len,
    42e7:	41 89 c5             	mov    %eax,%r13d
			if (len < 0) {
    42ea:	78 b8                	js     42a4 <l2cap_config_rsp+0x1e4>
			l2cap_send_cmd(conn, l2cap_get_ident(conn),
    42ec:	4c 89 e7             	mov    %r12,%rdi
    42ef:	e8 bc c1 ff ff       	callq  4b0 <l2cap_get_ident>
    42f4:	4c 8d 45 88          	lea    -0x78(%rbp),%r8
    42f8:	41 0f b7 cd          	movzwl %r13w,%ecx
    42fc:	0f b6 f0             	movzbl %al,%esi
    42ff:	ba 04 00 00 00       	mov    $0x4,%edx
    4304:	4c 89 e7             	mov    %r12,%rdi
    4307:	e8 b4 d0 ff ff       	callq  13c0 <l2cap_send_cmd>
			chan->num_conf_req++;
    430c:	80 43 6d 01          	addb   $0x1,0x6d(%rbx)
			if (result != L2CAP_CONF_SUCCESS)
    4310:	66 83 7d 86 00       	cmpw   $0x0,-0x7a(%rbp)
    4315:	0f 84 b6 fe ff ff    	je     41d1 <l2cap_config_rsp+0x111>
    431b:	e9 50 fe ff ff       	jmpq   4170 <l2cap_config_rsp+0xb0>
			len = l2cap_parse_conf_rsp(chan, rsp->data, len,
    4320:	49 8d 77 06          	lea    0x6(%r15),%rsi
    4324:	4c 8d 45 86          	lea    -0x7a(%rbp),%r8
    4328:	48 8d 4d 88          	lea    -0x78(%rbp),%rcx
    432c:	44 89 ea             	mov    %r13d,%edx
    432f:	48 89 df             	mov    %rbx,%rdi
    4332:	e8 09 dd ff ff       	callq  2040 <l2cap_parse_conf_rsp>
			if (len < 0) {
    4337:	85 c0                	test   %eax,%eax
    4339:	0f 88 65 ff ff ff    	js     42a4 <l2cap_config_rsp+0x1e4>
    433f:	f0 80 a3 81 00 00 00 	lock andb $0xfd,0x81(%rbx)
    4346:	fd 
		asm volatile(LOCK_PREFIX "orb %1,%0"
    4347:	f0 80 8b 80 00 00 00 	lock orb $0x4,0x80(%rbx)
    434e:	04 
						l2cap_build_conf_rsp(chan, buf,
    434f:	48 8d 75 88          	lea    -0x78(%rbp),%rsi
    4353:	31 c9                	xor    %ecx,%ecx
    4355:	31 d2                	xor    %edx,%edx
    4357:	48 89 df             	mov    %rbx,%rdi
    435a:	e8 c1 bd ff ff       	callq  120 <l2cap_build_conf_rsp>
			l2cap_send_cmd(conn, cmd->ident, L2CAP_CONF_RSP,
    435f:	41 0f b6 76 01       	movzbl 0x1(%r14),%esi
    4364:	4c 8d 45 88          	lea    -0x78(%rbp),%r8
    4368:	4c 89 e7             	mov    %r12,%rdi
    436b:	0f b7 c8             	movzwl %ax,%ecx
    436e:	ba 05 00 00 00       	mov    $0x5,%edx
	int err = 0;
    4373:	45 31 e4             	xor    %r12d,%r12d
			l2cap_send_cmd(conn, cmd->ident, L2CAP_CONF_RSP,
    4376:	e8 45 d0 ff ff       	callq  13c0 <l2cap_send_cmd>
    437b:	e9 f3 fd ff ff       	jmpq   4173 <l2cap_config_rsp+0xb3>
	while (len >= L2CAP_CONF_OPT_SIZE) {
    4380:	41 83 fd 01          	cmp    $0x1,%r13d
    4384:	7f 3d                	jg     43c3 <l2cap_config_rsp+0x303>
    4386:	e9 b9 00 00 00       	jmpq   4444 <l2cap_config_rsp+0x384>
    438b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
	switch (opt->len) {
    4390:	3c 04                	cmp    $0x4,%al
    4392:	74 7c                	je     4410 <l2cap_config_rsp+0x350>
    4394:	3c 05                	cmp    $0x5,%al
    4396:	75 68                	jne    4400 <l2cap_config_rsp+0x340>
static inline u64 get_unaligned_le64(const void *p)
    4398:	4d 8b 7f 02          	mov    0x2(%r15),%r15
	BT_DBG("type 0x%2.2x len %d val 0x%lx", *type, opt->len, *val);
    439c:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 43a3 <l2cap_config_rsp+0x2e3>
    43a3:	0f 85 90 03 00 00    	jne    4739 <l2cap_config_rsp+0x679>
		len -= l2cap_get_conf_opt(&rsp, &type, &olen, &val);
    43a9:	45 29 e3             	sub    %r12d,%r11d
		switch (type) {
    43ac:	41 80 fe 04          	cmp    $0x4,%r14b
    43b0:	0f 84 ea 00 00 00    	je     44a0 <l2cap_config_rsp+0x3e0>
	while (len >= L2CAP_CONF_OPT_SIZE) {
    43b6:	41 83 fb 01          	cmp    $0x1,%r11d
    43ba:	0f 8e 80 00 00 00    	jle    4440 <l2cap_config_rsp+0x380>
	*ptr += len;
    43c0:	4d 89 cf             	mov    %r9,%r15
	len = L2CAP_CONF_OPT_SIZE + opt->len;
    43c3:	41 0f b6 47 01       	movzbl 0x1(%r15),%eax
	*type = opt->type;
    43c8:	45 0f b6 37          	movzbl (%r15),%r14d
	len = L2CAP_CONF_OPT_SIZE + opt->len;
    43cc:	44 0f b6 e8          	movzbl %al,%r13d
	switch (opt->len) {
    43d0:	3c 02                	cmp    $0x2,%al
	len = L2CAP_CONF_OPT_SIZE + opt->len;
    43d2:	45 8d 65 02          	lea    0x2(%r13),%r12d
	*ptr += len;
    43d6:	49 63 d4             	movslq %r12d,%rdx
    43d9:	4d 8d 0c 17          	lea    (%r15,%rdx,1),%r9
	switch (opt->len) {
    43dd:	74 11                	je     43f0 <l2cap_config_rsp+0x330>
    43df:	77 af                	ja     4390 <l2cap_config_rsp+0x2d0>
    43e1:	3c 01                	cmp    $0x1,%al
    43e3:	75 1b                	jne    4400 <l2cap_config_rsp+0x340>
		*val = *((u8 *) opt->val);
    43e5:	45 0f b6 7f 02       	movzbl 0x2(%r15),%r15d
    43ea:	eb b0                	jmp    439c <l2cap_config_rsp+0x2dc>
    43ec:	0f 1f 40 00          	nopl   0x0(%rax)
		*val = get_unaligned_le16(opt->val);
    43f0:	45 0f b7 7f 02       	movzwl 0x2(%r15),%r15d
    43f5:	eb a5                	jmp    439c <l2cap_config_rsp+0x2dc>
    43f7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    43fe:	00 00 
		*val = (unsigned long) opt->val;
    4400:	49 83 c7 02          	add    $0x2,%r15
    4404:	eb 96                	jmp    439c <l2cap_config_rsp+0x2dc>
    4406:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    440d:	00 00 00 
		*val = get_unaligned_le32(opt->val);
    4410:	45 8b 7f 02          	mov    0x2(%r15),%r15d
    4414:	eb 86                	jmp    439c <l2cap_config_rsp+0x2dc>
    4416:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    441d:	00 00 00 
	asm volatile(LOCK_PREFIX "incl %0"
    4420:	f0 ff 43 14          	lock incl 0x14(%rbx)
    4424:	e9 70 fe ff ff       	jmpq   4299 <l2cap_config_rsp+0x1d9>
    4429:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		return 0;
    4430:	31 c0                	xor    %eax,%eax
    4432:	e9 4b fd ff ff       	jmpq   4182 <l2cap_config_rsp+0xc2>
    4437:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    443e:	00 00 
    4440:	0f b6 43 24          	movzbl 0x24(%rbx),%eax
    4444:	88 85 75 ff ff ff    	mov    %al,-0x8b(%rbp)
	rfc.max_pdu_size = cpu_to_le16(chan->imtu);
    444a:	0f b7 43 1e          	movzwl 0x1e(%rbx),%eax
	BT_ERR("Expected RFC option was not found, using defaults");
    444e:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
	rfc.monitor_timeout = cpu_to_le16(L2CAP_DEFAULT_MONITOR_TO);
    4455:	41 bf e0 2e 00 00    	mov    $0x2ee0,%r15d
	rfc.max_pdu_size = cpu_to_le16(chan->imtu);
    445b:	66 89 85 72 ff ff ff 	mov    %ax,-0x8e(%rbp)
	BT_ERR("Expected RFC option was not found, using defaults");
    4462:	31 c0                	xor    %eax,%eax
    4464:	e8 00 00 00 00       	callq  4469 <l2cap_config_rsp+0x3a9>
	rfc.retrans_timeout = cpu_to_le16(L2CAP_DEFAULT_RETRANS_TO);
    4469:	b8 d0 07 00 00       	mov    $0x7d0,%eax
	rfc.monitor_timeout = cpu_to_le16(L2CAP_DEFAULT_MONITOR_TO);
    446e:	66 44 89 bd 6e ff ff 	mov    %r15w,-0x92(%rbp)
    4475:	ff 
	rfc.retrans_timeout = cpu_to_le16(L2CAP_DEFAULT_RETRANS_TO);
    4476:	66 89 85 70 ff ff ff 	mov    %ax,-0x90(%rbp)
	switch (rfc.mode) {
    447d:	0f b6 85 75 ff ff ff 	movzbl -0x8b(%rbp),%eax
    4484:	3c 03                	cmp    $0x3,%al
    4486:	74 58                	je     44e0 <l2cap_config_rsp+0x420>
    4488:	3c 04                	cmp    $0x4,%al
    448a:	0f 85 39 fd ff ff    	jne    41c9 <l2cap_config_rsp+0x109>
		chan->mps    = le16_to_cpu(rfc.max_pdu_size);
    4490:	0f b7 85 72 ff ff ff 	movzwl -0x8e(%rbp),%eax
    4497:	66 89 43 7a          	mov    %ax,0x7a(%rbx)
    449b:	e9 29 fd ff ff       	jmpq   41c9 <l2cap_config_rsp+0x109>
			if (olen == sizeof(rfc))
    44a0:	41 83 fd 09          	cmp    $0x9,%r13d
    44a4:	75 d7                	jne    447d <l2cap_config_rsp+0x3bd>
				memcpy(&rfc, (void *)val, olen);
    44a6:	41 0f b6 07          	movzbl (%r15),%eax
    44aa:	88 85 75 ff ff ff    	mov    %al,-0x8b(%rbp)
    44b0:	41 0f b7 47 03       	movzwl 0x3(%r15),%eax
    44b5:	66 89 85 70 ff ff ff 	mov    %ax,-0x90(%rbp)
    44bc:	41 0f b7 47 05       	movzwl 0x5(%r15),%eax
    44c1:	66 89 85 6e ff ff ff 	mov    %ax,-0x92(%rbp)
    44c8:	41 0f b7 47 07       	movzwl 0x7(%r15),%eax
    44cd:	66 89 85 72 ff ff ff 	mov    %ax,-0x8e(%rbp)
    44d4:	eb a7                	jmp    447d <l2cap_config_rsp+0x3bd>
    44d6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    44dd:	00 00 00 
		chan->retrans_timeout = le16_to_cpu(rfc.retrans_timeout);
    44e0:	0f b7 85 70 ff ff ff 	movzwl -0x90(%rbp),%eax
    44e7:	66 89 43 76          	mov    %ax,0x76(%rbx)
		chan->monitor_timeout = le16_to_cpu(rfc.monitor_timeout);
    44eb:	0f b7 85 6e ff ff ff 	movzwl -0x92(%rbp),%eax
    44f2:	66 89 43 78          	mov    %ax,0x78(%rbx)
		chan->mps    = le16_to_cpu(rfc.max_pdu_size);
    44f6:	0f b7 85 72 ff ff ff 	movzwl -0x8e(%rbp),%eax
    44fd:	66 89 43 7a          	mov    %ax,0x7a(%rbx)
    4501:	e9 c3 fc ff ff       	jmpq   41c9 <l2cap_config_rsp+0x109>
	skb_queue_head_init(&chan->tx_q);
    4506:	48 8d 93 b8 02 00 00 	lea    0x2b8(%rbx),%rdx
	chan->next_tx_seq = 0;
    450d:	31 c9                	xor    %ecx,%ecx
	chan->expected_tx_seq = 0;
    450f:	31 f6                	xor    %esi,%esi
	chan->expected_ack_seq = 0;
    4511:	31 ff                	xor    %edi,%edi
	chan->unacked_frames = 0;
    4513:	45 31 c0             	xor    %r8d,%r8d
	chan->buffer_seq = 0;
    4516:	45 31 c9             	xor    %r9d,%r9d
	chan->frames_sent = 0;
    4519:	45 31 d2             	xor    %r10d,%r10d
	chan->last_acked_seq = 0;
    451c:	45 31 db             	xor    %r11d,%r11d
	chan->sdu_len = 0;
    451f:	45 31 e4             	xor    %r12d,%r12d
	spin_lock_init(&list->lock);
    4522:	45 31 ed             	xor    %r13d,%r13d
	if (chan->mode != L2CAP_MODE_ERTM)
    4525:	3c 03                	cmp    $0x3,%al
	chan->next_tx_seq = 0;
    4527:	66 89 8b 98 00 00 00 	mov    %cx,0x98(%rbx)
	chan->expected_tx_seq = 0;
    452e:	66 89 b3 9c 00 00 00 	mov    %si,0x9c(%rbx)
	chan->expected_ack_seq = 0;
    4535:	66 89 bb 9a 00 00 00 	mov    %di,0x9a(%rbx)
	chan->unacked_frames = 0;
    453c:	66 44 89 83 a8 00 00 	mov    %r8w,0xa8(%rbx)
    4543:	00 
	chan->buffer_seq = 0;
    4544:	66 44 89 8b 9e 00 00 	mov    %r9w,0x9e(%rbx)
    454b:	00 
	chan->num_acked = 0;
    454c:	c6 83 ae 00 00 00 00 	movb   $0x0,0xae(%rbx)
	chan->frames_sent = 0;
    4553:	66 44 89 93 a6 00 00 	mov    %r10w,0xa6(%rbx)
    455a:	00 
	chan->last_acked_seq = 0;
    455b:	66 44 89 9b a4 00 00 	mov    %r11w,0xa4(%rbx)
    4562:	00 
	chan->sdu = NULL;
    4563:	48 c7 83 b8 00 00 00 	movq   $0x0,0xb8(%rbx)
    456a:	00 00 00 00 
	chan->sdu_last_frag = NULL;
    456e:	48 c7 83 c0 00 00 00 	movq   $0x0,0xc0(%rbx)
    4575:	00 00 00 00 
	chan->sdu_len = 0;
    4579:	66 44 89 a3 b0 00 00 	mov    %r12w,0xb0(%rbx)
    4580:	00 
    4581:	66 44 89 ab cc 02 00 	mov    %r13w,0x2cc(%rbx)
    4588:	00 
	list->prev = list->next = (struct sk_buff *)list;
    4589:	48 89 93 b8 02 00 00 	mov    %rdx,0x2b8(%rbx)
    4590:	48 89 93 c0 02 00 00 	mov    %rdx,0x2c0(%rbx)
	list->qlen = 0;
    4597:	c7 83 c8 02 00 00 00 	movl   $0x0,0x2c8(%rbx)
    459e:	00 00 00 
	if (chan->mode != L2CAP_MODE_ERTM)
    45a1:	0f 85 76 fc ff ff    	jne    421d <l2cap_config_rsp+0x15d>
	INIT_DELAYED_WORK(&chan->retrans_timer, l2cap_retrans_timeout);
    45a7:	48 8d 83 68 01 00 00 	lea    0x168(%rbx),%rax
    45ae:	48 8d bb 80 01 00 00 	lea    0x180(%rbx),%rdi
    45b5:	31 d2                	xor    %edx,%edx
    45b7:	31 f6                	xor    %esi,%esi
	chan->rx_state = L2CAP_RX_STATE_RECV;
    45b9:	c6 43 7d 00          	movb   $0x0,0x7d(%rbx)
	chan->tx_state = L2CAP_TX_STATE_XMIT;
    45bd:	c6 43 7c 00          	movb   $0x0,0x7c(%rbx)
	list->next = list;
    45c1:	48 89 83 68 01 00 00 	mov    %rax,0x168(%rbx)
	list->prev = list;
    45c8:	48 89 83 70 01 00 00 	mov    %rax,0x170(%rbx)
	INIT_DELAYED_WORK(&chan->retrans_timer, l2cap_retrans_timeout);
    45cf:	48 c7 83 60 01 00 00 	movq   $0x900,0x160(%rbx)
    45d6:	00 09 00 00 
    45da:	48 c7 83 78 01 00 00 	movq   $0x0,0x178(%rbx)
    45e1:	00 00 00 00 
    45e5:	e8 00 00 00 00       	callq  45ea <l2cap_config_rsp+0x52a>
	INIT_DELAYED_WORK(&chan->monitor_timer, l2cap_monitor_timeout);
    45ea:	48 8d 83 d8 01 00 00 	lea    0x1d8(%rbx),%rax
    45f1:	48 8d bb f0 01 00 00 	lea    0x1f0(%rbx),%rdi
    45f8:	31 d2                	xor    %edx,%edx
    45fa:	31 f6                	xor    %esi,%esi
    45fc:	48 c7 83 d0 01 00 00 	movq   $0x900,0x1d0(%rbx)
    4603:	00 09 00 00 
    4607:	48 c7 83 e8 01 00 00 	movq   $0x0,0x1e8(%rbx)
    460e:	00 00 00 00 
	list->next = list;
    4612:	48 89 83 d8 01 00 00 	mov    %rax,0x1d8(%rbx)
	list->prev = list;
    4619:	48 89 83 e0 01 00 00 	mov    %rax,0x1e0(%rbx)
    4620:	e8 00 00 00 00       	callq  4625 <l2cap_config_rsp+0x565>
	INIT_DELAYED_WORK(&chan->ack_timer, l2cap_ack_timeout);
    4625:	48 8d 83 48 02 00 00 	lea    0x248(%rbx),%rax
    462c:	48 8d bb 60 02 00 00 	lea    0x260(%rbx),%rdi
    4633:	31 d2                	xor    %edx,%edx
    4635:	31 f6                	xor    %esi,%esi
    4637:	48 c7 83 40 02 00 00 	movq   $0x900,0x240(%rbx)
    463e:	00 09 00 00 
    4642:	48 c7 83 58 02 00 00 	movq   $0x0,0x258(%rbx)
    4649:	00 00 00 00 
	list->next = list;
    464d:	48 89 83 48 02 00 00 	mov    %rax,0x248(%rbx)
	list->prev = list;
    4654:	48 89 83 50 02 00 00 	mov    %rax,0x250(%rbx)
    465b:	e8 00 00 00 00       	callq  4660 <l2cap_config_rsp+0x5a0>
	skb_queue_head_init(&chan->srej_q);
    4660:	48 8d 83 d0 02 00 00 	lea    0x2d0(%rbx),%rax
	err = l2cap_seq_list_init(&chan->srej_list, chan->tx_win);
    4667:	0f b7 73 70          	movzwl 0x70(%rbx),%esi
	spin_lock_init(&list->lock);
    466b:	31 d2                	xor    %edx,%edx
    466d:	48 8d bb e8 02 00 00 	lea    0x2e8(%rbx),%rdi
    4674:	66 89 93 e4 02 00 00 	mov    %dx,0x2e4(%rbx)
	list->qlen = 0;
    467b:	c7 83 e0 02 00 00 00 	movl   $0x0,0x2e0(%rbx)
    4682:	00 00 00 
	list->prev = list->next = (struct sk_buff *)list;
    4685:	48 89 83 d0 02 00 00 	mov    %rax,0x2d0(%rbx)
    468c:	48 89 83 d8 02 00 00 	mov    %rax,0x2d8(%rbx)
	INIT_LIST_HEAD(&chan->srej_l);
    4693:	48 8d 83 08 03 00 00 	lea    0x308(%rbx),%rax
	list->next = list;
    469a:	48 89 83 08 03 00 00 	mov    %rax,0x308(%rbx)
	list->prev = list;
    46a1:	48 89 83 10 03 00 00 	mov    %rax,0x310(%rbx)
	err = l2cap_seq_list_init(&chan->srej_list, chan->tx_win);
    46a8:	e8 93 bb ff ff       	callq  240 <l2cap_seq_list_init>
	if (err < 0)
    46ad:	85 c0                	test   %eax,%eax
	err = l2cap_seq_list_init(&chan->srej_list, chan->tx_win);
    46af:	41 89 c4             	mov    %eax,%r12d
	if (err < 0)
    46b2:	78 1e                	js     46d2 <l2cap_config_rsp+0x612>
	return l2cap_seq_list_init(&chan->retrans_list, chan->remote_tx_win);
    46b4:	0f b7 b3 c8 00 00 00 	movzwl 0xc8(%rbx),%esi
    46bb:	48 8d bb f8 02 00 00 	lea    0x2f8(%rbx),%rdi
    46c2:	e8 79 bb ff ff       	callq  240 <l2cap_seq_list_init>
		if (err < 0)
    46c7:	85 c0                	test   %eax,%eax
	return l2cap_seq_list_init(&chan->retrans_list, chan->remote_tx_win);
    46c9:	41 89 c4             	mov    %eax,%r12d
		if (err < 0)
    46cc:	0f 89 4e fb ff ff    	jns    4220 <l2cap_config_rsp+0x160>
			l2cap_send_disconn_req(chan->conn, chan, -err);
    46d2:	48 8b 7b 08          	mov    0x8(%rbx),%rdi
    46d6:	44 89 e2             	mov    %r12d,%edx
    46d9:	48 89 de             	mov    %rbx,%rsi
    46dc:	f7 da                	neg    %edx
    46de:	e8 1d df ff ff       	callq  2600 <l2cap_send_disconn_req>
    46e3:	e9 8b fa ff ff       	jmpq   4173 <l2cap_config_rsp+0xb3>
		(addr[nr / BITS_PER_LONG])) != 0;
    46e8:	48 8b 83 80 00 00 00 	mov    0x80(%rbx),%rax
	else if (!test_bit(CONF_NO_FCS_RECV, &chan->conf_state))
    46ef:	a8 40                	test   $0x40,%al
    46f1:	0f 85 09 fb ff ff    	jne    4200 <l2cap_config_rsp+0x140>
		chan->fcs = L2CAP_FCS_CRC16;
    46f7:	c6 43 6f 01          	movb   $0x1,0x6f(%rbx)
    46fb:	e9 00 fb ff ff       	jmpq   4200 <l2cap_config_rsp+0x140>
}
    4700:	e8 00 00 00 00       	callq  4705 <l2cap_config_rsp+0x645>
	BT_DBG("scid 0x%4.4x flags 0x%2.2x result 0x%2.2x len %d", scid, flags,
    4705:	0f b7 8d 76 ff ff ff 	movzwl -0x8a(%rbp),%ecx
    470c:	45 89 e9             	mov    %r13d,%r9d
    470f:	89 da                	mov    %ebx,%edx
    4711:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    4718:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    471f:	31 c0                	xor    %eax,%eax
    4721:	44 89 ad 78 ff ff ff 	mov    %r13d,-0x88(%rbp)
    4728:	e8 00 00 00 00       	callq  472d <l2cap_config_rsp+0x66d>
    472d:	44 8b 9d 78 ff ff ff 	mov    -0x88(%rbp),%r11d
    4734:	e9 e1 f9 ff ff       	jmpq   411a <l2cap_config_rsp+0x5a>
	*type = opt->type;
    4739:	41 0f b6 d6          	movzbl %r14b,%edx
	BT_DBG("type 0x%2.2x len %d val 0x%lx", *type, opt->len, *val);
    473d:	4d 89 f8             	mov    %r15,%r8
    4740:	44 89 e9             	mov    %r13d,%ecx
    4743:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    474a:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    4751:	31 c0                	xor    %eax,%eax
    4753:	44 89 9d 68 ff ff ff 	mov    %r11d,-0x98(%rbp)
    475a:	4c 89 8d 78 ff ff ff 	mov    %r9,-0x88(%rbp)
    4761:	e8 00 00 00 00       	callq  4766 <l2cap_config_rsp+0x6a6>
    4766:	44 8b 9d 68 ff ff ff 	mov    -0x98(%rbp),%r11d
    476d:	4c 8b 8d 78 ff ff ff 	mov    -0x88(%rbp),%r9
    4774:	e9 30 fc ff ff       	jmpq   43a9 <l2cap_config_rsp+0x2e9>
	BT_DBG("chan %p, rsp %p, len %d", chan, rsp, len);
    4779:	45 89 e8             	mov    %r13d,%r8d
    477c:	4c 89 f9             	mov    %r15,%rcx
    477f:	48 89 da             	mov    %rbx,%rdx
    4782:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    4789:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    4790:	31 c0                	xor    %eax,%eax
    4792:	44 89 9d 78 ff ff ff 	mov    %r11d,-0x88(%rbp)
    4799:	e8 00 00 00 00       	callq  479e <l2cap_config_rsp+0x6de>
    479e:	44 8b 9d 78 ff ff ff 	mov    -0x88(%rbp),%r11d
    47a5:	e9 0f fa ff ff       	jmpq   41b9 <l2cap_config_rsp+0xf9>
	switch (state) {
    47aa:	0f b6 43 10          	movzbl 0x10(%rbx),%eax
    47ae:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    47b5:	83 e8 01             	sub    $0x1,%eax
    47b8:	83 f8 08             	cmp    $0x8,%eax
    47bb:	77 08                	ja     47c5 <l2cap_config_rsp+0x705>
    47bd:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    47c4:	00 
	BT_DBG("chan %p state %s timeout %ld", chan,
    47c5:	4d 89 e8             	mov    %r13,%r8
    47c8:	48 89 da             	mov    %rbx,%rdx
    47cb:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    47d2:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    47d9:	31 c0                	xor    %eax,%eax
    47db:	e8 00 00 00 00       	callq  47e0 <l2cap_config_rsp+0x720>
    47e0:	e9 98 fa ff ff       	jmpq   427d <l2cap_config_rsp+0x1bd>
    47e5:	90                   	nop
    47e6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    47ed:	00 00 00 

00000000000047f0 <l2cap_retransmit_one_frame>:
{
    47f0:	55                   	push   %rbp
    47f1:	48 89 e5             	mov    %rsp,%rbp
    47f4:	41 56                	push   %r14
    47f6:	41 55                	push   %r13
    47f8:	41 54                	push   %r12
    47fa:	53                   	push   %rbx
    47fb:	e8 00 00 00 00       	callq  4800 <l2cap_retransmit_one_frame+0x10>
	struct sk_buff *skb = list_->next;
    4800:	48 8b 9f b8 02 00 00 	mov    0x2b8(%rdi),%rbx
	skb = skb_peek(&chan->tx_q);
    4807:	48 8d 87 b8 02 00 00 	lea    0x2b8(%rdi),%rax
{
    480e:	49 89 fc             	mov    %rdi,%r12
    4811:	41 89 f5             	mov    %esi,%r13d
    4814:	89 f2                	mov    %esi,%edx
	if (skb == (struct sk_buff *)list_)
    4816:	48 39 d8             	cmp    %rbx,%rax
    4819:	0f 84 1b 01 00 00    	je     493a <l2cap_retransmit_one_frame+0x14a>
	if (!skb)
    481f:	48 85 db             	test   %rbx,%rbx
    4822:	75 18                	jne    483c <l2cap_retransmit_one_frame+0x4c>
    4824:	e9 11 01 00 00       	jmpq   493a <l2cap_retransmit_one_frame+0x14a>
    4829:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
	struct sk_buff *skb, *tx_skb;
    4830:	48 8b 1b             	mov    (%rbx),%rbx
		if (skb_queue_is_last(&chan->tx_q, skb))
    4833:	48 39 d8             	cmp    %rbx,%rax
    4836:	0f 84 fe 00 00 00    	je     493a <l2cap_retransmit_one_frame+0x14a>
	while (bt_cb(skb)->control.txseq != tx_seq) {
    483c:	66 39 53 34          	cmp    %dx,0x34(%rbx)
    4840:	75 ee                	jne    4830 <l2cap_retransmit_one_frame+0x40>
	if (bt_cb(skb)->control.retries == chan->remote_max_tx &&
    4842:	0f b6 43 36          	movzbl 0x36(%rbx),%eax
    4846:	41 3a 84 24 ca 00 00 	cmp    0xca(%r12),%al
    484d:	00 
    484e:	75 08                	jne    4858 <l2cap_retransmit_one_frame+0x68>
    4850:	84 c0                	test   %al,%al
    4852:	0f 85 4c 01 00 00    	jne    49a4 <l2cap_retransmit_one_frame+0x1b4>
	tx_skb = skb_clone(skb, GFP_ATOMIC);
    4858:	be 20 00 00 00       	mov    $0x20,%esi
    485d:	48 89 df             	mov    %rbx,%rdi
    4860:	e8 00 00 00 00       	callq  4865 <l2cap_retransmit_one_frame+0x75>
	bt_cb(skb)->control.retries++;
    4865:	80 43 36 01          	addb   $0x1,0x36(%rbx)
	tx_skb = skb_clone(skb, GFP_ATOMIC);
    4869:	49 89 c6             	mov    %rax,%r14
	control = __get_control(chan, tx_skb->data + L2CAP_HDR_SIZE);
    486c:	48 8b 90 e0 00 00 00 	mov    0xe0(%rax),%rdx
    4873:	49 8b 84 24 90 00 00 	mov    0x90(%r12),%rax
    487a:	00 
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    487b:	a8 10                	test   $0x10,%al
    487d:	0f 84 c5 00 00 00    	je     4948 <l2cap_retransmit_one_frame+0x158>
static inline u32 get_unaligned_le32(const void *p)
    4883:	8b 42 04             	mov    0x4(%rdx),%eax
    4886:	49 8b 94 24 90 00 00 	mov    0x90(%r12),%rdx
    488d:	00 
    488e:	48 c1 ea 04          	shr    $0x4,%rdx
    4892:	83 e2 01             	and    $0x1,%edx
		return L2CAP_EXT_CTRL_SAR;
    4895:	48 83 fa 01          	cmp    $0x1,%rdx
    4899:	19 d2                	sbb    %edx,%edx
    489b:	81 e2 00 c0 fd ff    	and    $0xfffdc000,%edx
    48a1:	81 c2 00 00 03 00    	add    $0x30000,%edx
	control &= __get_sar_mask(chan);
    48a7:	21 c2                	and    %eax,%edx
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    48a9:	f0 41 0f ba b4 24 88 	lock btrl $0x7,0x88(%r12)
    48b0:	00 00 00 07 
    48b4:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_FBIT, &chan->conn_state))
    48b6:	85 c0                	test   %eax,%eax
    48b8:	74 1d                	je     48d7 <l2cap_retransmit_one_frame+0xe7>
		(addr[nr / BITS_PER_LONG])) != 0;
    48ba:	49 8b 84 24 90 00 00 	mov    0x90(%r12),%rax
    48c1:	00 
    48c2:	48 c1 e8 04          	shr    $0x4,%rax
    48c6:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_FINAL;
    48c9:	48 83 f8 01          	cmp    $0x1,%rax
    48cd:	19 c0                	sbb    %eax,%eax
    48cf:	83 e0 7e             	and    $0x7e,%eax
    48d2:	83 c0 02             	add    $0x2,%eax
		control |= __set_ctrl_final(chan);
    48d5:	09 c2                	or     %eax,%edx
    48d7:	49 8b 8c 24 90 00 00 	mov    0x90(%r12),%rcx
    48de:	00 
	control |= __set_reqseq(chan, chan->buffer_seq);
    48df:	41 0f b7 84 24 9e 00 	movzwl 0x9e(%r12),%eax
    48e6:	00 00 
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    48e8:	83 e1 10             	and    $0x10,%ecx
    48eb:	0f 84 7f 00 00 00    	je     4970 <l2cap_retransmit_one_frame+0x180>
		return (reqseq << L2CAP_EXT_CTRL_REQSEQ_SHIFT) &
    48f1:	c1 e0 02             	shl    $0x2,%eax
    48f4:	0f b7 c0             	movzwl %ax,%eax
    48f7:	09 c2                	or     %eax,%edx
    48f9:	49 8b 84 24 90 00 00 	mov    0x90(%r12),%rax
    4900:	00 
	control |= __set_txseq(chan, tx_seq);
    4901:	45 0f b7 ed          	movzwl %r13w,%r13d
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4905:	a8 10                	test   $0x10,%al
    4907:	74 57                	je     4960 <l2cap_retransmit_one_frame+0x170>
		return (txseq << L2CAP_EXT_CTRL_TXSEQ_SHIFT) &
    4909:	41 c1 e5 12          	shl    $0x12,%r13d
    490d:	49 8b 8c 24 90 00 00 	mov    0x90(%r12),%rcx
    4914:	00 
    4915:	44 09 ea             	or     %r13d,%edx
	__put_control(chan, control, tx_skb->data + L2CAP_HDR_SIZE);
    4918:	49 8b b6 e0 00 00 00 	mov    0xe0(%r14),%rsi
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    491f:	83 e1 10             	and    $0x10,%ecx
    4922:	74 34                	je     4958 <l2cap_retransmit_one_frame+0x168>
	*((__le32 *)p) = cpu_to_le32(val);
    4924:	89 56 04             	mov    %edx,0x4(%rsi)
	if (chan->fcs == L2CAP_FCS_CRC16) {
    4927:	41 80 7c 24 6f 01    	cmpb   $0x1,0x6f(%r12)
    492d:	74 4e                	je     497d <l2cap_retransmit_one_frame+0x18d>
	l2cap_do_send(chan, tx_skb);
    492f:	4c 89 f6             	mov    %r14,%rsi
    4932:	4c 89 e7             	mov    %r12,%rdi
    4935:	e8 c6 bb ff ff       	callq  500 <l2cap_do_send>
}
    493a:	5b                   	pop    %rbx
    493b:	41 5c                	pop    %r12
    493d:	41 5d                	pop    %r13
    493f:	41 5e                	pop    %r14
    4941:	5d                   	pop    %rbp
    4942:	c3                   	retq   
    4943:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		return get_unaligned_le16(p);
    4948:	0f b7 42 04          	movzwl 0x4(%rdx),%eax
    494c:	e9 35 ff ff ff       	jmpq   4886 <l2cap_retransmit_one_frame+0x96>
    4951:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    4958:	66 89 56 04          	mov    %dx,0x4(%rsi)
    495c:	eb c9                	jmp    4927 <l2cap_retransmit_one_frame+0x137>
    495e:	66 90                	xchg   %ax,%ax
		return (txseq << L2CAP_CTRL_TXSEQ_SHIFT) & L2CAP_CTRL_TXSEQ;
    4960:	45 01 ed             	add    %r13d,%r13d
    4963:	41 83 e5 7e          	and    $0x7e,%r13d
    4967:	eb a4                	jmp    490d <l2cap_retransmit_one_frame+0x11d>
    4969:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		return (reqseq << L2CAP_CTRL_REQSEQ_SHIFT) & L2CAP_CTRL_REQSEQ;
    4970:	c1 e0 08             	shl    $0x8,%eax
    4973:	25 00 3f 00 00       	and    $0x3f00,%eax
    4978:	e9 7a ff ff ff       	jmpq   48f7 <l2cap_retransmit_one_frame+0x107>
						tx_skb->len - L2CAP_FCS_SIZE);
    497d:	41 8b 46 68          	mov    0x68(%r14),%eax
		fcs = crc16(0, (u8 *)tx_skb->data,
    4981:	49 8b b6 e0 00 00 00 	mov    0xe0(%r14),%rsi
    4988:	31 ff                	xor    %edi,%edi
    498a:	8d 50 fe             	lea    -0x2(%rax),%edx
    498d:	e8 00 00 00 00       	callq  4992 <l2cap_retransmit_one_frame+0x1a2>
				tx_skb->data + tx_skb->len - L2CAP_FCS_SIZE);
    4992:	41 8b 56 68          	mov    0x68(%r14),%edx
	*((__le16 *)p) = cpu_to_le16(val);
    4996:	49 8b 8e e0 00 00 00 	mov    0xe0(%r14),%rcx
    499d:	66 89 44 11 fe       	mov    %ax,-0x2(%rcx,%rdx,1)
    49a2:	eb 8b                	jmp    492f <l2cap_retransmit_one_frame+0x13f>
		l2cap_send_disconn_req(chan->conn, chan, ECONNABORTED);
    49a4:	49 8b 7c 24 08       	mov    0x8(%r12),%rdi
    49a9:	ba 67 00 00 00       	mov    $0x67,%edx
    49ae:	4c 89 e6             	mov    %r12,%rsi
    49b1:	e8 4a dc ff ff       	callq  2600 <l2cap_send_disconn_req>
		return;
    49b6:	e9 7f ff ff ff       	jmpq   493a <l2cap_retransmit_one_frame+0x14a>
    49bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000000049c0 <l2cap_add_to_srej_queue>:
{
    49c0:	55                   	push   %rbp
    49c1:	48 89 e5             	mov    %rsp,%rbp
    49c4:	53                   	push   %rbx
    49c5:	e8 00 00 00 00       	callq  49ca <l2cap_add_to_srej_queue+0xa>
	bt_cb(skb)->control.sar = sar;
    49ca:	0f b6 46 30          	movzbl 0x30(%rsi),%eax
    49ce:	83 e1 03             	and    $0x3,%ecx
	bt_cb(skb)->control.txseq = tx_seq;
    49d1:	66 89 56 34          	mov    %dx,0x34(%rsi)
	next_skb = skb_peek(&chan->srej_q);
    49d5:	4c 8d 97 d0 02 00 00 	lea    0x2d0(%rdi),%r10
	bt_cb(skb)->control.sar = sar;
    49dc:	c1 e1 04             	shl    $0x4,%ecx
{
    49df:	89 d3                	mov    %edx,%ebx
	bt_cb(skb)->control.sar = sar;
    49e1:	83 e0 cf             	and    $0xffffffcf,%eax
    49e4:	09 c8                	or     %ecx,%eax
		skb = NULL;
    49e6:	b9 00 00 00 00       	mov    $0x0,%ecx
    49eb:	88 46 30             	mov    %al,0x30(%rsi)
	struct sk_buff *skb = list_->next;
    49ee:	48 8b 87 d0 02 00 00 	mov    0x2d0(%rdi),%rax
	tx_seq_offset = __seq_offset(chan, tx_seq, chan->buffer_seq);
    49f5:	44 0f b7 8f 9e 00 00 	movzwl 0x9e(%rdi),%r9d
    49fc:	00 
		skb = NULL;
    49fd:	49 39 c2             	cmp    %rax,%r10
    4a00:	48 0f 44 c1          	cmove  %rcx,%rax
	if (seq1 >= seq2)
    4a04:	66 44 39 ca          	cmp    %r9w,%dx
    4a08:	72 6e                	jb     4a78 <l2cap_add_to_srej_queue+0xb8>
		return seq1 - seq2;
    4a0a:	0f b7 d2             	movzwl %dx,%edx
    4a0d:	45 0f b7 d9          	movzwl %r9w,%r11d
    4a11:	44 29 da             	sub    %r11d,%edx
    4a14:	eb 19                	jmp    4a2f <l2cap_add_to_srej_queue+0x6f>
    4a16:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    4a1d:	00 00 00 
    4a20:	44 29 d9             	sub    %r11d,%ecx
		if (next_tx_seq_offset > tx_seq_offset) {
    4a23:	39 ca                	cmp    %ecx,%edx
    4a25:	7c 2f                	jl     4a56 <l2cap_add_to_srej_queue+0x96>
	struct sk_buff *next_skb;
    4a27:	48 8b 00             	mov    (%rax),%rax
		if (skb_queue_is_last(&chan->srej_q, next_skb))
    4a2a:	49 39 c2             	cmp    %rax,%r10
    4a2d:	74 61                	je     4a90 <l2cap_add_to_srej_queue+0xd0>
	while (next_skb) {
    4a2f:	48 85 c0             	test   %rax,%rax
    4a32:	74 5c                	je     4a90 <l2cap_add_to_srej_queue+0xd0>
		if (bt_cb(next_skb)->control.txseq == tx_seq)
    4a34:	0f b7 48 34          	movzwl 0x34(%rax),%ecx
    4a38:	66 39 d9             	cmp    %bx,%cx
    4a3b:	74 7b                	je     4ab8 <l2cap_add_to_srej_queue+0xf8>
	if (seq1 >= seq2)
    4a3d:	66 41 39 c9          	cmp    %cx,%r9w
    4a41:	76 dd                	jbe    4a20 <l2cap_add_to_srej_queue+0x60>
		return chan->tx_win_max + 1 - seq2 + seq1;
    4a43:	44 0f b7 47 72       	movzwl 0x72(%rdi),%r8d
    4a48:	41 83 c0 01          	add    $0x1,%r8d
    4a4c:	45 29 d8             	sub    %r11d,%r8d
    4a4f:	44 01 c1             	add    %r8d,%ecx
		if (next_tx_seq_offset > tx_seq_offset) {
    4a52:	39 ca                	cmp    %ecx,%edx
    4a54:	7d d1                	jge    4a27 <l2cap_add_to_srej_queue+0x67>
	__skb_insert(newsk, next->prev, next, list);
    4a56:	48 8b 50 08          	mov    0x8(%rax),%rdx
	newsk->next = next;
    4a5a:	48 89 06             	mov    %rax,(%rsi)
	newsk->prev = prev;
    4a5d:	48 89 56 08          	mov    %rdx,0x8(%rsi)
	next->prev  = prev->next = newsk;
    4a61:	48 89 32             	mov    %rsi,(%rdx)
    4a64:	48 89 70 08          	mov    %rsi,0x8(%rax)
	list->qlen++;
    4a68:	83 87 e0 02 00 00 01 	addl   $0x1,0x2e0(%rdi)
			return 0;
    4a6f:	31 c0                	xor    %eax,%eax
}
    4a71:	5b                   	pop    %rbx
    4a72:	5d                   	pop    %rbp
    4a73:	c3                   	retq   
    4a74:	0f 1f 40 00          	nopl   0x0(%rax)
    4a78:	0f b7 4f 72          	movzwl 0x72(%rdi),%ecx
    4a7c:	45 0f b7 d9          	movzwl %r9w,%r11d
    4a80:	0f b7 d2             	movzwl %dx,%edx
    4a83:	83 c1 01             	add    $0x1,%ecx
    4a86:	44 29 d9             	sub    %r11d,%ecx
    4a89:	01 ca                	add    %ecx,%edx
	while (next_skb) {
    4a8b:	48 85 c0             	test   %rax,%rax
    4a8e:	75 a4                	jne    4a34 <l2cap_add_to_srej_queue+0x74>
	__skb_insert(newsk, next->prev, next, list);
    4a90:	48 8b 87 d8 02 00 00 	mov    0x2d8(%rdi),%rax
	newsk->next = next;
    4a97:	4c 89 16             	mov    %r10,(%rsi)
	newsk->prev = prev;
    4a9a:	48 89 46 08          	mov    %rax,0x8(%rsi)
	next->prev  = prev->next = newsk;
    4a9e:	48 89 30             	mov    %rsi,(%rax)
	return 0;
    4aa1:	31 c0                	xor    %eax,%eax
	list->qlen++;
    4aa3:	83 87 e0 02 00 00 01 	addl   $0x1,0x2e0(%rdi)
	next->prev  = prev->next = newsk;
    4aaa:	48 89 b7 d8 02 00 00 	mov    %rsi,0x2d8(%rdi)
}
    4ab1:	5b                   	pop    %rbx
    4ab2:	5d                   	pop    %rbp
    4ab3:	c3                   	retq   
    4ab4:	0f 1f 40 00          	nopl   0x0(%rax)
    4ab8:	5b                   	pop    %rbx
			return -EINVAL;
    4ab9:	b8 ea ff ff ff       	mov    $0xffffffea,%eax
}
    4abe:	5d                   	pop    %rbp
    4abf:	c3                   	retq   

0000000000004ac0 <l2cap_data_channel_sframe>:
{
    4ac0:	55                   	push   %rbp
    4ac1:	48 89 e5             	mov    %rsp,%rbp
    4ac4:	41 57                	push   %r15
    4ac6:	41 56                	push   %r14
    4ac8:	41 55                	push   %r13
    4aca:	49 89 d5             	mov    %rdx,%r13
    4acd:	41 54                	push   %r12
    4acf:	41 89 f4             	mov    %esi,%r12d
    4ad2:	53                   	push   %rbx
    4ad3:	48 89 fb             	mov    %rdi,%rbx
    4ad6:	48 83 ec 28          	sub    $0x28,%rsp
	BT_DBG("chan %p rx_control 0x%8.8x len %d", chan, rx_control, skb->len);
    4ada:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 4ae1 <l2cap_data_channel_sframe+0x21>
    4ae1:	0f 85 60 0e 00 00    	jne    5947 <l2cap_data_channel_sframe+0xe87>
    4ae7:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4aee:	a8 10                	test   $0x10,%al
		return ctrl & L2CAP_EXT_CTRL_FINAL;
    4af0:	44 89 e0             	mov    %r12d,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4af3:	0f 84 2f 01 00 00    	je     4c28 <l2cap_data_channel_sframe+0x168>
		return ctrl & L2CAP_EXT_CTRL_FINAL;
    4af9:	d1 e8                	shr    %eax
    4afb:	83 e0 01             	and    $0x1,%eax
	if (__is_ctrl_final(chan, rx_control) &&
    4afe:	84 c0                	test   %al,%al
    4b00:	74 0f                	je     4b11 <l2cap_data_channel_sframe+0x51>
    4b02:	48 8b 83 88 00 00 00 	mov    0x88(%rbx),%rax
    4b09:	a8 02                	test   $0x2,%al
    4b0b:	0f 85 9f 04 00 00    	jne    4fb0 <l2cap_data_channel_sframe+0x4f0>
    4b11:	4c 8d bb 88 00 00 00 	lea    0x88(%rbx),%r15
    4b18:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4b1f:	a8 10                	test   $0x10,%al
		return (ctrl & L2CAP_EXT_CTRL_SUPERVISE) >>
    4b21:	44 89 e0             	mov    %r12d,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4b24:	0f 84 0e 01 00 00    	je     4c38 <l2cap_data_channel_sframe+0x178>
		return (ctrl & L2CAP_EXT_CTRL_SUPERVISE) >>
    4b2a:	25 00 00 03 00       	and    $0x30000,%eax
    4b2f:	c1 e8 10             	shr    $0x10,%eax
	switch (__get_ctrl_super(chan, rx_control)) {
    4b32:	3c 02                	cmp    $0x2,%al
    4b34:	0f 84 0c 01 00 00    	je     4c46 <l2cap_data_channel_sframe+0x186>
    4b3a:	3c 03                	cmp    $0x3,%al
    4b3c:	0f 84 ce 03 00 00    	je     4f10 <l2cap_data_channel_sframe+0x450>
    4b42:	3c 01                	cmp    $0x1,%al
    4b44:	0f 84 06 03 00 00    	je     4e50 <l2cap_data_channel_sframe+0x390>
	BT_DBG("chan %p, req_seq %d ctrl 0x%8.8x", chan,
    4b4a:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 4b51 <l2cap_data_channel_sframe+0x91>
    4b51:	0f 85 43 0e 00 00    	jne    599a <l2cap_data_channel_sframe+0xeda>
    4b57:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4b5e:	a8 10                	test   $0x10,%al
		return (ctrl & L2CAP_EXT_CTRL_REQSEQ) >>
    4b60:	44 89 e0             	mov    %r12d,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4b63:	0f 85 a7 04 00 00    	jne    5010 <l2cap_data_channel_sframe+0x550>
		return (ctrl & L2CAP_CTRL_REQSEQ) >> L2CAP_CTRL_REQSEQ_SHIFT;
    4b69:	25 00 3f 00 00       	and    $0x3f00,%eax
    4b6e:	c1 e8 08             	shr    $0x8,%eax
	chan->expected_ack_seq = __get_reqseq(chan, rx_control);
    4b71:	66 89 83 9a 00 00 00 	mov    %ax,0x9a(%rbx)
	l2cap_drop_acked_frames(chan);
    4b78:	48 89 df             	mov    %rbx,%rdi
    4b7b:	e8 b0 d9 ff ff       	callq  2530 <l2cap_drop_acked_frames>
    4b80:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4b87:	a8 10                	test   $0x10,%al
		return ctrl & L2CAP_EXT_CTRL_POLL;
    4b89:	44 89 e0             	mov    %r12d,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4b8c:	0f 84 fe 04 00 00    	je     5090 <l2cap_data_channel_sframe+0x5d0>
		return ctrl & L2CAP_EXT_CTRL_POLL;
    4b92:	c1 e8 12             	shr    $0x12,%eax
    4b95:	83 e0 01             	and    $0x1,%eax
	if (__is_ctrl_poll(chan, rx_control)) {
    4b98:	84 c0                	test   %al,%al
    4b9a:	0f 84 b0 04 00 00    	je     5050 <l2cap_data_channel_sframe+0x590>
		asm volatile(LOCK_PREFIX "orb %1,%0"
    4ba0:	f0 41 80 0f 80       	lock orb $0x80,(%r15)
		(addr[nr / BITS_PER_LONG])) != 0;
    4ba5:	48 8b 83 88 00 00 00 	mov    0x88(%rbx),%rax
		if (test_bit(CONN_SREJ_SENT, &chan->conn_state)) {
    4bac:	a8 01                	test   $0x1,%al
    4bae:	0f 84 6c 09 00 00    	je     5520 <l2cap_data_channel_sframe+0xa60>
    4bb4:	48 8b 83 88 00 00 00 	mov    0x88(%rbx),%rax
			if (test_bit(CONN_REMOTE_BUSY, &chan->conn_state) &&
    4bbb:	a8 10                	test   $0x10,%al
    4bbd:	74 52                	je     4c11 <l2cap_data_channel_sframe+0x151>
    4bbf:	66 83 bb a8 00 00 00 	cmpw   $0x0,0xa8(%rbx)
    4bc6:	00 
    4bc7:	74 48                	je     4c11 <l2cap_data_channel_sframe+0x151>
				__set_retrans_timer(chan);
    4bc9:	bf d0 07 00 00       	mov    $0x7d0,%edi
    4bce:	4c 8d b3 60 01 00 00 	lea    0x160(%rbx),%r14
    4bd5:	e8 00 00 00 00       	callq  4bda <l2cap_data_channel_sframe+0x11a>
	BT_DBG("chan %p state %s timeout %ld", chan,
    4bda:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 4be1 <l2cap_data_channel_sframe+0x121>
    4be1:	49 89 c4             	mov    %rax,%r12
    4be4:	0f 85 a9 0e 00 00    	jne    5a93 <l2cap_data_channel_sframe+0xfd3>
	ret = del_timer_sync(&work->timer);
    4bea:	48 8d bb 80 01 00 00 	lea    0x180(%rbx),%rdi
    4bf1:	e8 00 00 00 00       	callq  4bf6 <l2cap_data_channel_sframe+0x136>
	if (ret)
    4bf6:	85 c0                	test   %eax,%eax
    4bf8:	0f 84 9d 0b 00 00    	je     579b <l2cap_data_channel_sframe+0xcdb>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    4bfe:	f0 80 a3 60 01 00 00 	lock andb $0xfe,0x160(%rbx)
    4c05:	fe 
	schedule_delayed_work(work, timeout);
    4c06:	4c 89 e6             	mov    %r12,%rsi
    4c09:	4c 89 f7             	mov    %r14,%rdi
    4c0c:	e8 00 00 00 00       	callq  4c11 <l2cap_data_channel_sframe+0x151>
    4c11:	f0 41 80 27 ef       	lock andb $0xef,(%r15)
			l2cap_send_srejtail(chan);
    4c16:	48 89 df             	mov    %rbx,%rdi
    4c19:	e8 f2 e1 ff ff       	callq  2e10 <l2cap_send_srejtail>
    4c1e:	e9 cd 02 00 00       	jmpq   4ef0 <l2cap_data_channel_sframe+0x430>
    4c23:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		return ctrl & L2CAP_CTRL_FINAL;
    4c28:	c1 e8 07             	shr    $0x7,%eax
    4c2b:	83 e0 01             	and    $0x1,%eax
    4c2e:	e9 cb fe ff ff       	jmpq   4afe <l2cap_data_channel_sframe+0x3e>
    4c33:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		return (ctrl & L2CAP_CTRL_SUPERVISE) >> L2CAP_CTRL_SUPER_SHIFT;
    4c38:	83 e0 0c             	and    $0xc,%eax
    4c3b:	c1 e8 02             	shr    $0x2,%eax
	switch (__get_ctrl_super(chan, rx_control)) {
    4c3e:	3c 02                	cmp    $0x2,%al
    4c40:	0f 85 f4 fe ff ff    	jne    4b3a <l2cap_data_channel_sframe+0x7a>
		(addr[nr / BITS_PER_LONG])) != 0;
    4c46:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
		return (ctrl & L2CAP_EXT_CTRL_REQSEQ) >>
    4c4d:	45 89 e6             	mov    %r12d,%r14d
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4c50:	a8 10                	test   $0x10,%al
    4c52:	0f 85 c8 03 00 00    	jne    5020 <l2cap_data_channel_sframe+0x560>
		return (ctrl & L2CAP_CTRL_REQSEQ) >> L2CAP_CTRL_REQSEQ_SHIFT;
    4c58:	41 81 e6 00 3f 00 00 	and    $0x3f00,%r14d
    4c5f:	41 c1 ee 08          	shr    $0x8,%r14d
	BT_DBG("chan %p, req_seq %d ctrl 0x%8.8x", chan, tx_seq, rx_control);
    4c63:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 4c6a <l2cap_data_channel_sframe+0x1aa>
    4c6a:	0f 85 af 0d 00 00    	jne    5a1f <l2cap_data_channel_sframe+0xf5f>
		asm volatile(LOCK_PREFIX "orb %1,%0"
    4c70:	f0 41 80 0f 10       	lock orb $0x10,(%r15)
	chan->expected_ack_seq = tx_seq;
    4c75:	66 44 89 b3 9a 00 00 	mov    %r14w,0x9a(%rbx)
    4c7c:	00 
	l2cap_drop_acked_frames(chan);
    4c7d:	48 89 df             	mov    %rbx,%rdi
    4c80:	e8 ab d8 ff ff       	callq  2530 <l2cap_drop_acked_frames>
		(addr[nr / BITS_PER_LONG])) != 0;
    4c85:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4c8c:	a8 10                	test   $0x10,%al
		return ctrl & L2CAP_EXT_CTRL_POLL;
    4c8e:	44 89 e0             	mov    %r12d,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4c91:	0f 84 a9 03 00 00    	je     5040 <l2cap_data_channel_sframe+0x580>
		return ctrl & L2CAP_EXT_CTRL_POLL;
    4c97:	c1 e8 12             	shr    $0x12,%eax
    4c9a:	83 e0 01             	and    $0x1,%eax
	if (__is_ctrl_poll(chan, rx_control))
    4c9d:	84 c0                	test   %al,%al
    4c9f:	74 05                	je     4ca6 <l2cap_data_channel_sframe+0x1e6>
		asm volatile(LOCK_PREFIX "orb %1,%0"
    4ca1:	f0 41 80 0f 80       	lock orb $0x80,(%r15)
		(addr[nr / BITS_PER_LONG])) != 0;
    4ca6:	48 8b 83 88 00 00 00 	mov    0x88(%rbx),%rax
	if (!test_bit(CONN_SREJ_SENT, &chan->conn_state)) {
    4cad:	a8 01                	test   $0x1,%al
    4caf:	0f 84 cb 04 00 00    	je     5180 <l2cap_data_channel_sframe+0x6c0>
    4cb5:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4cbc:	a8 10                	test   $0x10,%al
    4cbe:	0f 84 4c 04 00 00    	je     5110 <l2cap_data_channel_sframe+0x650>
		return ctrl & L2CAP_EXT_CTRL_POLL;
    4cc4:	41 c1 ec 12          	shr    $0x12,%r12d
    4cc8:	41 83 e4 01          	and    $0x1,%r12d
	if (__is_ctrl_poll(chan, rx_control)) {
    4ccc:	45 84 e4             	test   %r12b,%r12b
    4ccf:	0f 85 e3 06 00 00    	jne    53b8 <l2cap_data_channel_sframe+0x8f8>
	if (chan->state != BT_CONNECTED)
    4cd5:	80 7b 10 01          	cmpb   $0x1,0x10(%rbx)
    4cd9:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	struct l2cap_conn *conn = chan->conn;
    4ce0:	4c 8b 73 08          	mov    0x8(%rbx),%r14
	if (chan->state != BT_CONNECTED)
    4ce4:	0f 85 06 02 00 00    	jne    4ef0 <l2cap_data_channel_sframe+0x430>
    4cea:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    4cf1:	48 c1 e8 04          	shr    $0x4,%rax
    4cf5:	83 e0 01             	and    $0x1,%eax
		hlen = L2CAP_EXT_HDR_SIZE;
    4cf8:	48 83 f8 01          	cmp    $0x1,%rax
    4cfc:	45 19 e4             	sbb    %r12d,%r12d
    4cff:	41 83 e4 fe          	and    $0xfffffffe,%r12d
    4d03:	41 83 c4 08          	add    $0x8,%r12d
		hlen += L2CAP_FCS_SIZE;
    4d07:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    4d0b:	41 8d 44 24 02       	lea    0x2(%r12),%eax
    4d10:	44 0f 44 e0          	cmove  %eax,%r12d
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    4d14:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 4d1b <l2cap_data_channel_sframe+0x25b>
    4d1b:	0f 85 d5 0d 00 00    	jne    5af6 <l2cap_data_channel_sframe+0x1036>
	count = min_t(unsigned int, conn->mtu, hlen);
    4d21:	45 8b 76 20          	mov    0x20(%r14),%r14d
    4d25:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    4d2c:	45 39 f4             	cmp    %r14d,%r12d
    4d2f:	45 0f 46 f4          	cmovbe %r12d,%r14d
    4d33:	44 89 75 c8          	mov    %r14d,-0x38(%rbp)
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    4d37:	f0 41 0f ba 37 07    	lock btrl $0x7,(%r15)
    4d3d:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_FBIT, &chan->conn_state))
    4d3f:	85 c0                	test   %eax,%eax
	control |= __set_sframe(chan);
    4d41:	41 be 01 00 00 00    	mov    $0x1,%r14d
	if (test_and_clear_bit(CONN_SEND_FBIT, &chan->conn_state))
    4d47:	74 1d                	je     4d66 <l2cap_data_channel_sframe+0x2a6>
		(addr[nr / BITS_PER_LONG])) != 0;
    4d49:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    4d50:	48 c1 e8 04          	shr    $0x4,%rax
    4d54:	83 e0 01             	and    $0x1,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4d57:	48 83 f8 01          	cmp    $0x1,%rax
    4d5b:	45 19 f6             	sbb    %r14d,%r14d
    4d5e:	41 83 e6 7e          	and    $0x7e,%r14d
    4d62:	41 83 c6 03          	add    $0x3,%r14d
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    4d66:	f0 41 0f ba 37 03    	lock btrl $0x3,(%r15)
    4d6c:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_PBIT, &chan->conn_state))
    4d6e:	85 c0                	test   %eax,%eax
    4d70:	74 21                	je     4d93 <l2cap_data_channel_sframe+0x2d3>
		(addr[nr / BITS_PER_LONG])) != 0;
    4d72:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    4d79:	48 c1 e8 04          	shr    $0x4,%rax
    4d7d:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_POLL;
    4d80:	48 83 f8 01          	cmp    $0x1,%rax
    4d84:	19 c0                	sbb    %eax,%eax
    4d86:	25 10 00 fc ff       	and    $0xfffc0010,%eax
    4d8b:	05 00 00 04 00       	add    $0x40000,%eax
		control |= __set_ctrl_poll(chan);
    4d90:	41 09 c6             	or     %eax,%r14d
	if ((skb = alloc_skb(len + BT_SKB_RESERVE, how))) {
    4d93:	8b 45 c8             	mov    -0x38(%rbp),%eax
	return __alloc_skb(size, priority, 0, NUMA_NO_NODE);
    4d96:	31 d2                	xor    %edx,%edx
    4d98:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    4d9d:	be 20 00 00 00       	mov    $0x20,%esi
    4da2:	8d 78 08             	lea    0x8(%rax),%edi
    4da5:	e8 00 00 00 00       	callq  4daa <l2cap_data_channel_sframe+0x2ea>
    4daa:	48 85 c0             	test   %rax,%rax
    4dad:	49 89 c7             	mov    %rax,%r15
    4db0:	0f 84 3a 01 00 00    	je     4ef0 <l2cap_data_channel_sframe+0x430>
	skb->data += len;
    4db6:	48 83 80 e0 00 00 00 	addq   $0x8,0xe0(%rax)
    4dbd:	08 
	skb->tail += len;
    4dbe:	83 80 cc 00 00 00 08 	addl   $0x8,0xcc(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    4dc5:	be 04 00 00 00       	mov    $0x4,%esi
    4dca:	48 89 c7             	mov    %rax,%rdi
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    4dcd:	41 83 ec 04          	sub    $0x4,%r12d
		bt_cb(skb)->incoming  = 0;
    4dd1:	c6 40 29 00          	movb   $0x0,0x29(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    4dd5:	e8 00 00 00 00       	callq  4dda <l2cap_data_channel_sframe+0x31a>
    4dda:	48 89 c1             	mov    %rax,%rcx
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    4ddd:	66 44 89 20          	mov    %r12w,(%rax)
	lh->cid = cpu_to_le16(chan->dcid);
    4de1:	0f b7 43 1a          	movzwl 0x1a(%rbx),%eax
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    4de5:	4c 89 ff             	mov    %r15,%rdi
	lh->cid = cpu_to_le16(chan->dcid);
    4de8:	48 89 4d c0          	mov    %rcx,-0x40(%rbp)
    4dec:	66 89 41 02          	mov    %ax,0x2(%rcx)
    4df0:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
    4df7:	48 c1 ea 04          	shr    $0x4,%rdx
    4dfb:	83 e2 01             	and    $0x1,%edx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4dfe:	48 83 fa 01          	cmp    $0x1,%rdx
    4e02:	19 f6                	sbb    %esi,%esi
    4e04:	83 e6 fe             	and    $0xfffffffe,%esi
    4e07:	83 c6 04             	add    $0x4,%esi
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    4e0a:	e8 00 00 00 00       	callq  4e0f <l2cap_data_channel_sframe+0x34f>
    4e0f:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4e16:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
    4e1a:	83 e2 10             	and    $0x10,%edx
    4e1d:	0f 84 4d 09 00 00    	je     5770 <l2cap_data_channel_sframe+0xcb0>
	*((__le32 *)p) = cpu_to_le32(val);
    4e23:	44 89 30             	mov    %r14d,(%rax)
	if (chan->fcs == L2CAP_FCS_CRC16) {
    4e26:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    4e2a:	0f 84 d6 0a 00 00    	je     5906 <l2cap_data_channel_sframe+0xe46>
	skb->priority = HCI_PRIO_MAX;
    4e30:	41 c7 47 78 07 00 00 	movl   $0x7,0x78(%r15)
    4e37:	00 
	l2cap_do_send(chan, skb);
    4e38:	4c 89 fe             	mov    %r15,%rsi
    4e3b:	48 89 df             	mov    %rbx,%rdi
    4e3e:	e8 bd b6 ff ff       	callq  500 <l2cap_do_send>
    4e43:	e9 a8 00 00 00       	jmpq   4ef0 <l2cap_data_channel_sframe+0x430>
    4e48:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    4e4f:	00 
    4e50:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
		return (ctrl & L2CAP_EXT_CTRL_REQSEQ) >>
    4e57:	45 89 e6             	mov    %r12d,%r14d
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4e5a:	a8 10                	test   $0x10,%al
    4e5c:	0f 85 9e 01 00 00    	jne    5000 <l2cap_data_channel_sframe+0x540>
		return (ctrl & L2CAP_CTRL_REQSEQ) >> L2CAP_CTRL_REQSEQ_SHIFT;
    4e62:	41 81 e6 00 3f 00 00 	and    $0x3f00,%r14d
    4e69:	41 c1 ee 08          	shr    $0x8,%r14d
	BT_DBG("chan %p, req_seq %d ctrl 0x%8.8x", chan, tx_seq, rx_control);
    4e6d:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 4e74 <l2cap_data_channel_sframe+0x3b4>
    4e74:	0f 85 5d 0b 00 00    	jne    59d7 <l2cap_data_channel_sframe+0xf17>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    4e7a:	f0 41 80 27 ef       	lock andb $0xef,(%r15)
	chan->expected_ack_seq = tx_seq;
    4e7f:	66 44 89 b3 9a 00 00 	mov    %r14w,0x9a(%rbx)
    4e86:	00 
	l2cap_drop_acked_frames(chan);
    4e87:	48 89 df             	mov    %rbx,%rdi
    4e8a:	e8 a1 d6 ff ff       	callq  2530 <l2cap_drop_acked_frames>
		(addr[nr / BITS_PER_LONG])) != 0;
    4e8f:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4e96:	a8 10                	test   $0x10,%al
    4e98:	0f 84 62 02 00 00    	je     5100 <l2cap_data_channel_sframe+0x640>
		return ctrl & L2CAP_EXT_CTRL_FINAL;
    4e9e:	41 d1 ec             	shr    %r12d
    4ea1:	41 83 e4 01          	and    $0x1,%r12d
	if (__is_ctrl_final(chan, rx_control)) {
    4ea5:	45 84 e4             	test   %r12b,%r12b
    4ea8:	0f 84 02 02 00 00    	je     50b0 <l2cap_data_channel_sframe+0x5f0>
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    4eae:	f0 41 0f ba 37 06    	lock btrl $0x6,(%r15)
    4eb4:	19 c0                	sbb    %eax,%eax
		if (!test_and_clear_bit(CONN_REJ_ACT, &chan->conn_state))
    4eb6:	85 c0                	test   %eax,%eax
    4eb8:	75 36                	jne    4ef0 <l2cap_data_channel_sframe+0x430>
	return list->next == (struct sk_buff *)list;
    4eba:	48 8b 83 b8 02 00 00 	mov    0x2b8(%rbx),%rax
	if (!skb_queue_empty(&chan->tx_q))
    4ec1:	48 8d 93 b8 02 00 00 	lea    0x2b8(%rbx),%rdx
    4ec8:	48 39 d0             	cmp    %rdx,%rax
    4ecb:	74 07                	je     4ed4 <l2cap_data_channel_sframe+0x414>
		chan->tx_send_head = chan->tx_q.next;
    4ecd:	48 89 83 b0 02 00 00 	mov    %rax,0x2b0(%rbx)
	chan->next_tx_seq = chan->expected_ack_seq;
    4ed4:	0f b7 83 9a 00 00 00 	movzwl 0x9a(%rbx),%eax
    4edb:	66 89 83 98 00 00 00 	mov    %ax,0x98(%rbx)
	ret = l2cap_ertm_send(chan);
    4ee2:	48 89 df             	mov    %rbx,%rdi
    4ee5:	e8 66 db ff ff       	callq  2a50 <l2cap_ertm_send>
    4eea:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
	kfree_skb(skb);
    4ef0:	4c 89 ef             	mov    %r13,%rdi
    4ef3:	e8 00 00 00 00       	callq  4ef8 <l2cap_data_channel_sframe+0x438>
}
    4ef8:	48 83 c4 28          	add    $0x28,%rsp
    4efc:	31 c0                	xor    %eax,%eax
    4efe:	5b                   	pop    %rbx
    4eff:	41 5c                	pop    %r12
    4f01:	41 5d                	pop    %r13
    4f03:	41 5e                	pop    %r14
    4f05:	41 5f                	pop    %r15
    4f07:	5d                   	pop    %rbp
    4f08:	c3                   	retq   
    4f09:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		(addr[nr / BITS_PER_LONG])) != 0;
    4f10:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
		return (ctrl & L2CAP_EXT_CTRL_REQSEQ) >>
    4f17:	45 89 e6             	mov    %r12d,%r14d
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4f1a:	a8 10                	test   $0x10,%al
    4f1c:	0f 85 0e 01 00 00    	jne    5030 <l2cap_data_channel_sframe+0x570>
		return (ctrl & L2CAP_CTRL_REQSEQ) >> L2CAP_CTRL_REQSEQ_SHIFT;
    4f22:	41 81 e6 00 3f 00 00 	and    $0x3f00,%r14d
    4f29:	41 c1 ee 08          	shr    $0x8,%r14d
	BT_DBG("chan %p, req_seq %d ctrl 0x%8.8x", chan, tx_seq, rx_control);
    4f2d:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 4f34 <l2cap_data_channel_sframe+0x474>
    4f34:	0f 85 c1 0a 00 00    	jne    59fb <l2cap_data_channel_sframe+0xf3b>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    4f3a:	f0 41 80 27 ef       	lock andb $0xef,(%r15)
		(addr[nr / BITS_PER_LONG])) != 0;
    4f3f:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4f46:	a8 10                	test   $0x10,%al
		return ctrl & L2CAP_EXT_CTRL_POLL;
    4f48:	44 89 e0             	mov    %r12d,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4f4b:	0f 84 4f 01 00 00    	je     50a0 <l2cap_data_channel_sframe+0x5e0>
		return ctrl & L2CAP_EXT_CTRL_POLL;
    4f51:	c1 e8 12             	shr    $0x12,%eax
    4f54:	83 e0 01             	and    $0x1,%eax
	if (__is_ctrl_poll(chan, rx_control)) {
    4f57:	84 c0                	test   %al,%al
    4f59:	0f 85 d1 01 00 00    	jne    5130 <l2cap_data_channel_sframe+0x670>
    4f5f:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    4f66:	a8 10                	test   $0x10,%al
    4f68:	0f 84 b2 01 00 00    	je     5120 <l2cap_data_channel_sframe+0x660>
		return ctrl & L2CAP_EXT_CTRL_FINAL;
    4f6e:	41 d1 ec             	shr    %r12d
    4f71:	41 83 e4 01          	and    $0x1,%r12d
	} else if (__is_ctrl_final(chan, rx_control)) {
    4f75:	45 84 e4             	test   %r12b,%r12b
    4f78:	0f 84 62 05 00 00    	je     54e0 <l2cap_data_channel_sframe+0xa20>
    4f7e:	48 8b 83 88 00 00 00 	mov    0x88(%rbx),%rax
		if (test_bit(CONN_SREJ_ACT, &chan->conn_state) &&
    4f85:	a8 04                	test   $0x4,%al
    4f87:	74 0e                	je     4f97 <l2cap_data_channel_sframe+0x4d7>
    4f89:	66 44 3b b3 a2 00 00 	cmp    0xa2(%rbx),%r14w
    4f90:	00 
    4f91:	0f 84 69 05 00 00    	je     5500 <l2cap_data_channel_sframe+0xa40>
			l2cap_retransmit_one_frame(chan, tx_seq);
    4f97:	41 0f b7 f6          	movzwl %r14w,%esi
    4f9b:	48 89 df             	mov    %rbx,%rdi
    4f9e:	e8 4d f8 ff ff       	callq  47f0 <l2cap_retransmit_one_frame>
    4fa3:	e9 48 ff ff ff       	jmpq   4ef0 <l2cap_data_channel_sframe+0x430>
    4fa8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    4faf:	00 
	ret = del_timer_sync(&work->timer);
    4fb0:	48 8d bb f0 01 00 00 	lea    0x1f0(%rbx),%rdi
    4fb7:	e8 00 00 00 00       	callq  4fbc <l2cap_data_channel_sframe+0x4fc>
	if (ret)
    4fbc:	85 c0                	test   %eax,%eax
    4fbe:	74 17                	je     4fd7 <l2cap_data_channel_sframe+0x517>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    4fc0:	f0 80 a3 d0 01 00 00 	lock andb $0xfe,0x1d0(%rbx)
    4fc7:	fe 
	asm volatile(LOCK_PREFIX "decl %0; sete %1"
    4fc8:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    4fcc:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    4fcf:	84 c0                	test   %al,%al
    4fd1:	0f 85 39 05 00 00    	jne    5510 <l2cap_data_channel_sframe+0xa50>
		if (chan->unacked_frames > 0)
    4fd7:	66 83 bb a8 00 00 00 	cmpw   $0x0,0xa8(%rbx)
    4fde:	00 
    4fdf:	0f 85 ab 04 00 00    	jne    5490 <l2cap_data_channel_sframe+0x9d0>
			: CONST_MASK_ADDR(nr, addr)
    4fe5:	4c 8d 8b 88 00 00 00 	lea    0x88(%rbx),%r9
		asm volatile(LOCK_PREFIX "andb %1,%0"
    4fec:	f0 80 a3 88 00 00 00 	lock andb $0xfd,0x88(%rbx)
    4ff3:	fd 
    4ff4:	4d 89 cf             	mov    %r9,%r15
    4ff7:	e9 1c fb ff ff       	jmpq   4b18 <l2cap_data_channel_sframe+0x58>
    4ffc:	0f 1f 40 00          	nopl   0x0(%rax)
		return (ctrl & L2CAP_EXT_CTRL_REQSEQ) >>
    5000:	41 81 e6 fc ff 00 00 	and    $0xfffc,%r14d
    5007:	41 c1 ee 02          	shr    $0x2,%r14d
    500b:	e9 5d fe ff ff       	jmpq   4e6d <l2cap_data_channel_sframe+0x3ad>
    5010:	25 fc ff 00 00       	and    $0xfffc,%eax
    5015:	c1 e8 02             	shr    $0x2,%eax
    5018:	e9 54 fb ff ff       	jmpq   4b71 <l2cap_data_channel_sframe+0xb1>
    501d:	0f 1f 00             	nopl   (%rax)
    5020:	41 81 e6 fc ff 00 00 	and    $0xfffc,%r14d
    5027:	41 c1 ee 02          	shr    $0x2,%r14d
    502b:	e9 33 fc ff ff       	jmpq   4c63 <l2cap_data_channel_sframe+0x1a3>
    5030:	41 81 e6 fc ff 00 00 	and    $0xfffc,%r14d
    5037:	41 c1 ee 02          	shr    $0x2,%r14d
    503b:	e9 ed fe ff ff       	jmpq   4f2d <l2cap_data_channel_sframe+0x46d>
		return ctrl & L2CAP_CTRL_POLL;
    5040:	c1 e8 04             	shr    $0x4,%eax
    5043:	83 e0 01             	and    $0x1,%eax
    5046:	e9 52 fc ff ff       	jmpq   4c9d <l2cap_data_channel_sframe+0x1dd>
    504b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		(addr[nr / BITS_PER_LONG])) != 0;
    5050:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    5057:	a8 10                	test   $0x10,%al
    5059:	0f 84 11 04 00 00    	je     5470 <l2cap_data_channel_sframe+0x9b0>
		return ctrl & L2CAP_EXT_CTRL_FINAL;
    505f:	41 d1 ec             	shr    %r12d
    5062:	41 83 e4 01          	and    $0x1,%r12d
	} else if (__is_ctrl_final(chan, rx_control)) {
    5066:	45 84 e4             	test   %r12b,%r12b
    5069:	0f 84 59 03 00 00    	je     53c8 <l2cap_data_channel_sframe+0x908>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    506f:	f0 41 80 27 ef       	lock andb $0xef,(%r15)
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    5074:	f0 41 0f ba 37 06    	lock btrl $0x6,(%r15)
    507a:	19 c0                	sbb    %eax,%eax
		if (!test_and_clear_bit(CONN_REJ_ACT, &chan->conn_state))
    507c:	85 c0                	test   %eax,%eax
    507e:	0f 84 36 fe ff ff    	je     4eba <l2cap_data_channel_sframe+0x3fa>
    5084:	e9 67 fe ff ff       	jmpq   4ef0 <l2cap_data_channel_sframe+0x430>
    5089:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		return ctrl & L2CAP_CTRL_POLL;
    5090:	c1 e8 04             	shr    $0x4,%eax
    5093:	83 e0 01             	and    $0x1,%eax
    5096:	e9 fd fa ff ff       	jmpq   4b98 <l2cap_data_channel_sframe+0xd8>
    509b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    50a0:	c1 e8 04             	shr    $0x4,%eax
    50a3:	83 e0 01             	and    $0x1,%eax
    50a6:	e9 ac fe ff ff       	jmpq   4f57 <l2cap_data_channel_sframe+0x497>
    50ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    50b0:	48 8b 83 b8 02 00 00 	mov    0x2b8(%rbx),%rax
	if (!skb_queue_empty(&chan->tx_q))
    50b7:	48 8d 93 b8 02 00 00 	lea    0x2b8(%rbx),%rdx
    50be:	48 39 d0             	cmp    %rdx,%rax
    50c1:	74 07                	je     50ca <l2cap_data_channel_sframe+0x60a>
		chan->tx_send_head = chan->tx_q.next;
    50c3:	48 89 83 b0 02 00 00 	mov    %rax,0x2b0(%rbx)
	chan->next_tx_seq = chan->expected_ack_seq;
    50ca:	0f b7 83 9a 00 00 00 	movzwl 0x9a(%rbx),%eax
	ret = l2cap_ertm_send(chan);
    50d1:	48 89 df             	mov    %rbx,%rdi
	chan->next_tx_seq = chan->expected_ack_seq;
    50d4:	66 89 83 98 00 00 00 	mov    %ax,0x98(%rbx)
	ret = l2cap_ertm_send(chan);
    50db:	e8 70 d9 ff ff       	callq  2a50 <l2cap_ertm_send>
		(addr[nr / BITS_PER_LONG])) != 0;
    50e0:	48 8b 83 88 00 00 00 	mov    0x88(%rbx),%rax
		if (test_bit(CONN_WAIT_F, &chan->conn_state))
    50e7:	a8 02                	test   $0x2,%al
    50e9:	0f 84 01 fe ff ff    	je     4ef0 <l2cap_data_channel_sframe+0x430>
		asm volatile(LOCK_PREFIX "orb %1,%0"
    50ef:	f0 41 80 0f 40       	lock orb $0x40,(%r15)
    50f4:	e9 f7 fd ff ff       	jmpq   4ef0 <l2cap_data_channel_sframe+0x430>
    50f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		return ctrl & L2CAP_CTRL_FINAL;
    5100:	41 c1 ec 07          	shr    $0x7,%r12d
    5104:	41 83 e4 01          	and    $0x1,%r12d
    5108:	e9 98 fd ff ff       	jmpq   4ea5 <l2cap_data_channel_sframe+0x3e5>
    510d:	0f 1f 00             	nopl   (%rax)
		return ctrl & L2CAP_CTRL_POLL;
    5110:	41 c1 ec 04          	shr    $0x4,%r12d
    5114:	41 83 e4 01          	and    $0x1,%r12d
    5118:	e9 af fb ff ff       	jmpq   4ccc <l2cap_data_channel_sframe+0x20c>
    511d:	0f 1f 00             	nopl   (%rax)
		return ctrl & L2CAP_CTRL_FINAL;
    5120:	41 c1 ec 07          	shr    $0x7,%r12d
    5124:	41 83 e4 01          	and    $0x1,%r12d
    5128:	e9 48 fe ff ff       	jmpq   4f75 <l2cap_data_channel_sframe+0x4b5>
    512d:	0f 1f 00             	nopl   (%rax)
		chan->expected_ack_seq = tx_seq;
    5130:	66 44 89 b3 9a 00 00 	mov    %r14w,0x9a(%rbx)
    5137:	00 
		l2cap_drop_acked_frames(chan);
    5138:	48 89 df             	mov    %rbx,%rdi
    513b:	e8 f0 d3 ff ff       	callq  2530 <l2cap_drop_acked_frames>
    5140:	f0 41 80 0f 80       	lock orb $0x80,(%r15)
		l2cap_retransmit_one_frame(chan, tx_seq);
    5145:	41 0f b7 f6          	movzwl %r14w,%esi
    5149:	48 89 df             	mov    %rbx,%rdi
    514c:	e8 9f f6 ff ff       	callq  47f0 <l2cap_retransmit_one_frame>
		l2cap_ertm_send(chan);
    5151:	48 89 df             	mov    %rbx,%rdi
    5154:	e8 f7 d8 ff ff       	callq  2a50 <l2cap_ertm_send>
		(addr[nr / BITS_PER_LONG])) != 0;
    5159:	48 8b 83 88 00 00 00 	mov    0x88(%rbx),%rax
		if (test_bit(CONN_WAIT_F, &chan->conn_state)) {
    5160:	a8 02                	test   $0x2,%al
    5162:	0f 84 88 fd ff ff    	je     4ef0 <l2cap_data_channel_sframe+0x430>
			chan->srej_save_reqseq = tx_seq;
    5168:	66 44 89 b3 a2 00 00 	mov    %r14w,0xa2(%rbx)
    516f:	00 
		asm volatile(LOCK_PREFIX "orb %1,%0"
    5170:	f0 41 80 0f 04       	lock orb $0x4,(%r15)
    5175:	e9 76 fd ff ff       	jmpq   4ef0 <l2cap_data_channel_sframe+0x430>
    517a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
	ret = del_timer_sync(&work->timer);
    5180:	48 8d bb 80 01 00 00 	lea    0x180(%rbx),%rdi
    5187:	e8 00 00 00 00       	callq  518c <l2cap_data_channel_sframe+0x6cc>
	if (ret)
    518c:	85 c0                	test   %eax,%eax
    518e:	74 20                	je     51b0 <l2cap_data_channel_sframe+0x6f0>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    5190:	f0 80 a3 60 01 00 00 	lock andb $0xfe,0x160(%rbx)
    5197:	fe 
    5198:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    519c:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    519f:	84 c0                	test   %al,%al
    51a1:	74 0d                	je     51b0 <l2cap_data_channel_sframe+0x6f0>
		kfree(c);
    51a3:	48 89 df             	mov    %rbx,%rdi
    51a6:	e8 00 00 00 00       	callq  51ab <l2cap_data_channel_sframe+0x6eb>
    51ab:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		(addr[nr / BITS_PER_LONG])) != 0;
    51b0:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    51b7:	a8 10                	test   $0x10,%al
    51b9:	0f 85 c1 02 00 00    	jne    5480 <l2cap_data_channel_sframe+0x9c0>
		return ctrl & L2CAP_CTRL_POLL;
    51bf:	41 c1 ec 04          	shr    $0x4,%r12d
    51c3:	41 83 e4 01          	and    $0x1,%r12d
		if (__is_ctrl_poll(chan, rx_control))
    51c7:	45 84 e4             	test   %r12b,%r12b
    51ca:	0f 84 20 fd ff ff    	je     4ef0 <l2cap_data_channel_sframe+0x430>
    51d0:	48 8b 83 88 00 00 00 	mov    0x88(%rbx),%rax
	if (test_bit(CONN_LOCAL_BUSY, &chan->conn_state)) {
    51d7:	a8 20                	test   $0x20,%al
    51d9:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    51e0:	0f 84 aa 05 00 00    	je     5790 <l2cap_data_channel_sframe+0xcd0>
    51e6:	48 c1 e8 04          	shr    $0x4,%rax
    51ea:	83 e0 01             	and    $0x1,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    51ed:	48 83 f8 01          	cmp    $0x1,%rax
    51f1:	45 19 e4             	sbb    %r12d,%r12d
    51f4:	41 81 e4 08 00 fe ff 	and    $0xfffe0008,%r12d
    51fb:	41 81 c4 80 00 02 00 	add    $0x20080,%r12d
		asm volatile(LOCK_PREFIX "orb %1,%0"
    5202:	f0 80 8b 89 00 00 00 	lock orb $0x1,0x89(%rbx)
    5209:	01 
	control |= __set_reqseq(chan, chan->buffer_seq);
    520a:	0f b7 93 9e 00 00 00 	movzwl 0x9e(%rbx),%edx
		(addr[nr / BITS_PER_LONG])) != 0;
    5211:	48 8b 8b 90 00 00 00 	mov    0x90(%rbx),%rcx
		return (reqseq << L2CAP_CTRL_REQSEQ_SHIFT) & L2CAP_CTRL_REQSEQ;
    5218:	89 d0                	mov    %edx,%eax
    521a:	c1 e0 08             	shl    $0x8,%eax
    521d:	25 00 3f 00 00       	and    $0x3f00,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    5222:	83 e1 10             	and    $0x10,%ecx
    5225:	74 0a                	je     5231 <l2cap_data_channel_sframe+0x771>
		return (reqseq << L2CAP_EXT_CTRL_REQSEQ_SHIFT) &
    5227:	8d 04 95 00 00 00 00 	lea    0x0(,%rdx,4),%eax
    522e:	0f b7 c0             	movzwl %ax,%eax
	if (chan->state != BT_CONNECTED)
    5231:	80 7b 10 01          	cmpb   $0x1,0x10(%rbx)
	struct l2cap_conn *conn = chan->conn;
    5235:	4c 8b 73 08          	mov    0x8(%rbx),%r14
	if (chan->state != BT_CONNECTED)
    5239:	0f 85 b1 fc ff ff    	jne    4ef0 <l2cap_data_channel_sframe+0x430>
    523f:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
    5246:	48 c1 ea 04          	shr    $0x4,%rdx
    524a:	83 e2 01             	and    $0x1,%edx
		hlen = L2CAP_EXT_HDR_SIZE;
    524d:	48 83 fa 01          	cmp    $0x1,%rdx
    5251:	45 19 c9             	sbb    %r9d,%r9d
    5254:	41 83 e1 fe          	and    $0xfffffffe,%r9d
    5258:	41 83 c1 08          	add    $0x8,%r9d
		hlen += L2CAP_FCS_SIZE;
    525c:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    5260:	41 8d 51 02          	lea    0x2(%r9),%edx
    5264:	44 0f 44 ca          	cmove  %edx,%r9d
	control |= __set_reqseq(chan, chan->buffer_seq);
    5268:	41 09 c4             	or     %eax,%r12d
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    526b:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 5272 <l2cap_data_channel_sframe+0x7b2>
    5272:	0f 85 56 08 00 00    	jne    5ace <l2cap_data_channel_sframe+0x100e>
	count = min_t(unsigned int, conn->mtu, hlen);
    5278:	45 8b 76 20          	mov    0x20(%r14),%r14d
    527c:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    5283:	45 39 f1             	cmp    %r14d,%r9d
    5286:	45 0f 46 f1          	cmovbe %r9d,%r14d
	control |= __set_sframe(chan);
    528a:	41 83 cc 01          	or     $0x1,%r12d
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    528e:	f0 41 0f ba 37 07    	lock btrl $0x7,(%r15)
    5294:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_FBIT, &chan->conn_state))
    5296:	85 c0                	test   %eax,%eax
    5298:	74 1d                	je     52b7 <l2cap_data_channel_sframe+0x7f7>
		(addr[nr / BITS_PER_LONG])) != 0;
    529a:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    52a1:	48 c1 e8 04          	shr    $0x4,%rax
    52a5:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_FINAL;
    52a8:	48 83 f8 01          	cmp    $0x1,%rax
    52ac:	19 c0                	sbb    %eax,%eax
    52ae:	83 e0 7e             	and    $0x7e,%eax
    52b1:	83 c0 02             	add    $0x2,%eax
		control |= __set_ctrl_final(chan);
    52b4:	41 09 c4             	or     %eax,%r12d
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    52b7:	f0 41 0f ba 37 03    	lock btrl $0x3,(%r15)
    52bd:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_PBIT, &chan->conn_state))
    52bf:	85 c0                	test   %eax,%eax
    52c1:	74 21                	je     52e4 <l2cap_data_channel_sframe+0x824>
		(addr[nr / BITS_PER_LONG])) != 0;
    52c3:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    52ca:	48 c1 e8 04          	shr    $0x4,%rax
    52ce:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_POLL;
    52d1:	48 83 f8 01          	cmp    $0x1,%rax
    52d5:	19 c0                	sbb    %eax,%eax
    52d7:	25 10 00 fc ff       	and    $0xfffc0010,%eax
    52dc:	05 00 00 04 00       	add    $0x40000,%eax
		control |= __set_ctrl_poll(chan);
    52e1:	41 09 c4             	or     %eax,%r12d
	if ((skb = alloc_skb(len + BT_SKB_RESERVE, how))) {
    52e4:	41 8d 7e 08          	lea    0x8(%r14),%edi
	return __alloc_skb(size, priority, 0, NUMA_NO_NODE);
    52e8:	31 d2                	xor    %edx,%edx
    52ea:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    52ef:	be 20 00 00 00       	mov    $0x20,%esi
    52f4:	44 89 4d c8          	mov    %r9d,-0x38(%rbp)
    52f8:	e8 00 00 00 00       	callq  52fd <l2cap_data_channel_sframe+0x83d>
    52fd:	48 85 c0             	test   %rax,%rax
    5300:	49 89 c7             	mov    %rax,%r15
    5303:	0f 84 e7 fb ff ff    	je     4ef0 <l2cap_data_channel_sframe+0x430>
	skb->data += len;
    5309:	48 83 80 e0 00 00 00 	addq   $0x8,0xe0(%rax)
    5310:	08 
	skb->tail += len;
    5311:	83 80 cc 00 00 00 08 	addl   $0x8,0xcc(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    5318:	be 04 00 00 00       	mov    $0x4,%esi
    531d:	48 89 c7             	mov    %rax,%rdi
		bt_cb(skb)->incoming  = 0;
    5320:	c6 40 29 00          	movb   $0x0,0x29(%rax)
    5324:	e8 00 00 00 00       	callq  5329 <l2cap_data_channel_sframe+0x869>
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    5329:	44 8b 4d c8          	mov    -0x38(%rbp),%r9d
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    532d:	49 89 c0             	mov    %rax,%r8
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    5330:	4c 89 ff             	mov    %r15,%rdi
	lh->cid = cpu_to_le16(chan->dcid);
    5333:	4c 89 45 c8          	mov    %r8,-0x38(%rbp)
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    5337:	41 8d 41 fc          	lea    -0x4(%r9),%eax
    533b:	66 41 89 00          	mov    %ax,(%r8)
	lh->cid = cpu_to_le16(chan->dcid);
    533f:	0f b7 43 1a          	movzwl 0x1a(%rbx),%eax
    5343:	66 41 89 40 02       	mov    %ax,0x2(%r8)
    5348:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
    534f:	48 c1 ea 04          	shr    $0x4,%rdx
    5353:	83 e2 01             	and    $0x1,%edx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    5356:	48 83 fa 01          	cmp    $0x1,%rdx
    535a:	19 f6                	sbb    %esi,%esi
    535c:	83 e6 fe             	and    $0xfffffffe,%esi
    535f:	83 c6 04             	add    $0x4,%esi
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    5362:	e8 00 00 00 00       	callq  5367 <l2cap_data_channel_sframe+0x8a7>
    5367:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    536e:	4c 8b 45 c8          	mov    -0x38(%rbp),%r8
    5372:	83 e2 10             	and    $0x10,%edx
    5375:	0f 84 ac 05 00 00    	je     5927 <l2cap_data_channel_sframe+0xe67>
    537b:	44 89 20             	mov    %r12d,(%rax)
	if (chan->fcs == L2CAP_FCS_CRC16) {
    537e:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    5382:	0f 85 a8 fa ff ff    	jne    4e30 <l2cap_data_channel_sframe+0x370>
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    5388:	41 8d 56 fe          	lea    -0x2(%r14),%edx
    538c:	4c 89 c6             	mov    %r8,%rsi
    538f:	48 63 d2             	movslq %edx,%rdx
    5392:	31 ff                	xor    %edi,%edi
    5394:	e8 00 00 00 00       	callq  5399 <l2cap_data_channel_sframe+0x8d9>
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    5399:	be 02 00 00 00       	mov    $0x2,%esi
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    539e:	41 89 c4             	mov    %eax,%r12d
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    53a1:	4c 89 ff             	mov    %r15,%rdi
    53a4:	e8 00 00 00 00       	callq  53a9 <l2cap_data_channel_sframe+0x8e9>
	*((__le16 *)p) = cpu_to_le16(val);
    53a9:	66 44 89 20          	mov    %r12w,(%rax)
    53ad:	e9 7e fa ff ff       	jmpq   4e30 <l2cap_data_channel_sframe+0x370>
    53b2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		l2cap_send_srejtail(chan);
    53b8:	48 89 df             	mov    %rbx,%rdi
    53bb:	e8 50 da ff ff       	callq  2e10 <l2cap_send_srejtail>
    53c0:	e9 2b fb ff ff       	jmpq   4ef0 <l2cap_data_channel_sframe+0x430>
    53c5:	0f 1f 00             	nopl   (%rax)
    53c8:	48 8b 83 88 00 00 00 	mov    0x88(%rbx),%rax
		if (test_bit(CONN_REMOTE_BUSY, &chan->conn_state) &&
    53cf:	a8 10                	test   $0x10,%al
    53d1:	74 55                	je     5428 <l2cap_data_channel_sframe+0x968>
    53d3:	66 83 bb a8 00 00 00 	cmpw   $0x0,0xa8(%rbx)
    53da:	00 
    53db:	74 4b                	je     5428 <l2cap_data_channel_sframe+0x968>
			__set_retrans_timer(chan);
    53dd:	bf d0 07 00 00       	mov    $0x7d0,%edi
    53e2:	4c 8d b3 60 01 00 00 	lea    0x160(%rbx),%r14
    53e9:	e8 00 00 00 00       	callq  53ee <l2cap_data_channel_sframe+0x92e>
	BT_DBG("chan %p state %s timeout %ld", chan,
    53ee:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 53f5 <l2cap_data_channel_sframe+0x935>
    53f5:	49 89 c4             	mov    %rax,%r12
    53f8:	0f 85 52 07 00 00    	jne    5b50 <l2cap_data_channel_sframe+0x1090>
	ret = del_timer_sync(&work->timer);
    53fe:	48 8d bb 80 01 00 00 	lea    0x180(%rbx),%rdi
    5405:	e8 00 00 00 00       	callq  540a <l2cap_data_channel_sframe+0x94a>
	if (ret)
    540a:	85 c0                	test   %eax,%eax
    540c:	0f 84 0c 05 00 00    	je     591e <l2cap_data_channel_sframe+0xe5e>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    5412:	f0 80 a3 60 01 00 00 	lock andb $0xfe,0x160(%rbx)
    5419:	fe 
	schedule_delayed_work(work, timeout);
    541a:	4c 89 e6             	mov    %r12,%rsi
    541d:	4c 89 f7             	mov    %r14,%rdi
    5420:	e8 00 00 00 00       	callq  5425 <l2cap_data_channel_sframe+0x965>
    5425:	0f 1f 00             	nopl   (%rax)
    5428:	f0 41 80 27 ef       	lock andb $0xef,(%r15)
		(addr[nr / BITS_PER_LONG])) != 0;
    542d:	48 8b 83 88 00 00 00 	mov    0x88(%rbx),%rax
		if (test_bit(CONN_SREJ_SENT, &chan->conn_state))
    5434:	a8 01                	test   $0x1,%al
    5436:	0f 84 a6 fa ff ff    	je     4ee2 <l2cap_data_channel_sframe+0x422>
	ret = del_timer_sync(&work->timer);
    543c:	48 8d bb 60 02 00 00 	lea    0x260(%rbx),%rdi
    5443:	e8 00 00 00 00       	callq  5448 <l2cap_data_channel_sframe+0x988>
	if (ret)
    5448:	85 c0                	test   %eax,%eax
    544a:	74 17                	je     5463 <l2cap_data_channel_sframe+0x9a3>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    544c:	f0 80 a3 40 02 00 00 	lock andb $0xfe,0x240(%rbx)
    5453:	fe 
    5454:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    5458:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    545b:	84 c0                	test   %al,%al
    545d:	0f 85 ae 04 00 00    	jne    5911 <l2cap_data_channel_sframe+0xe51>
	__l2cap_send_ack(chan);
    5463:	48 89 df             	mov    %rbx,%rdi
    5466:	e8 85 e7 ff ff       	callq  3bf0 <__l2cap_send_ack>
    546b:	e9 80 fa ff ff       	jmpq   4ef0 <l2cap_data_channel_sframe+0x430>
		return ctrl & L2CAP_CTRL_FINAL;
    5470:	41 c1 ec 07          	shr    $0x7,%r12d
    5474:	41 83 e4 01          	and    $0x1,%r12d
    5478:	e9 e9 fb ff ff       	jmpq   5066 <l2cap_data_channel_sframe+0x5a6>
    547d:	0f 1f 00             	nopl   (%rax)
		return ctrl & L2CAP_EXT_CTRL_POLL;
    5480:	41 c1 ec 12          	shr    $0x12,%r12d
    5484:	41 83 e4 01          	and    $0x1,%r12d
    5488:	e9 3a fd ff ff       	jmpq   51c7 <l2cap_data_channel_sframe+0x707>
    548d:	0f 1f 00             	nopl   (%rax)
			__set_retrans_timer(chan);
    5490:	bf d0 07 00 00       	mov    $0x7d0,%edi
    5495:	4c 8d bb 60 01 00 00 	lea    0x160(%rbx),%r15
    549c:	e8 00 00 00 00       	callq  54a1 <l2cap_data_channel_sframe+0x9e1>
	BT_DBG("chan %p state %s timeout %ld", chan,
    54a1:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 54a8 <l2cap_data_channel_sframe+0x9e8>
    54a8:	49 89 c6             	mov    %rax,%r14
    54ab:	0f 85 64 06 00 00    	jne    5b15 <l2cap_data_channel_sframe+0x1055>
	ret = del_timer_sync(&work->timer);
    54b1:	48 8d bb 80 01 00 00 	lea    0x180(%rbx),%rdi
    54b8:	e8 00 00 00 00       	callq  54bd <l2cap_data_channel_sframe+0x9fd>
	if (ret)
    54bd:	85 c0                	test   %eax,%eax
    54bf:	0f 84 9b 02 00 00    	je     5760 <l2cap_data_channel_sframe+0xca0>
    54c5:	f0 80 a3 60 01 00 00 	lock andb $0xfe,0x160(%rbx)
    54cc:	fe 
	schedule_delayed_work(work, timeout);
    54cd:	4c 89 f6             	mov    %r14,%rsi
    54d0:	4c 89 ff             	mov    %r15,%rdi
    54d3:	e8 00 00 00 00       	callq  54d8 <l2cap_data_channel_sframe+0xa18>
    54d8:	e9 08 fb ff ff       	jmpq   4fe5 <l2cap_data_channel_sframe+0x525>
    54dd:	0f 1f 00             	nopl   (%rax)
		l2cap_retransmit_one_frame(chan, tx_seq);
    54e0:	41 0f b7 f6          	movzwl %r14w,%esi
    54e4:	48 89 df             	mov    %rbx,%rdi
    54e7:	e8 04 f3 ff ff       	callq  47f0 <l2cap_retransmit_one_frame>
		(addr[nr / BITS_PER_LONG])) != 0;
    54ec:	48 8b 83 88 00 00 00 	mov    0x88(%rbx),%rax
		if (test_bit(CONN_WAIT_F, &chan->conn_state)) {
    54f3:	a8 02                	test   $0x2,%al
    54f5:	0f 85 6d fc ff ff    	jne    5168 <l2cap_data_channel_sframe+0x6a8>
    54fb:	e9 f0 f9 ff ff       	jmpq   4ef0 <l2cap_data_channel_sframe+0x430>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    5500:	f0 41 80 27 fb       	lock andb $0xfb,(%r15)
    5505:	e9 e6 f9 ff ff       	jmpq   4ef0 <l2cap_data_channel_sframe+0x430>
    550a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		kfree(c);
    5510:	48 89 df             	mov    %rbx,%rdi
    5513:	e8 00 00 00 00       	callq  5518 <l2cap_data_channel_sframe+0xa58>
    5518:	e9 ba fa ff ff       	jmpq   4fd7 <l2cap_data_channel_sframe+0x517>
    551d:	0f 1f 00             	nopl   (%rax)
	chan->frames_sent = 0;
    5520:	31 c0                	xor    %eax,%eax
	control |= __set_reqseq(chan, chan->buffer_seq);
    5522:	44 0f b7 a3 9e 00 00 	movzwl 0x9e(%rbx),%r12d
    5529:	00 
	chan->frames_sent = 0;
    552a:	66 89 83 a6 00 00 00 	mov    %ax,0xa6(%rbx)
		(addr[nr / BITS_PER_LONG])) != 0;
    5531:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    5538:	a8 10                	test   $0x10,%al
    553a:	0f 84 40 02 00 00    	je     5780 <l2cap_data_channel_sframe+0xcc0>
		return (reqseq << L2CAP_EXT_CTRL_REQSEQ_SHIFT) &
    5540:	41 c1 e4 02          	shl    $0x2,%r12d
    5544:	45 0f b7 e4          	movzwl %r12w,%r12d
    5548:	48 8b 83 88 00 00 00 	mov    0x88(%rbx),%rax
	if (test_bit(CONN_LOCAL_BUSY, &chan->conn_state)) {
    554f:	a8 20                	test   $0x20,%al
    5551:	74 37                	je     558a <l2cap_data_channel_sframe+0xaca>
    5553:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	struct l2cap_conn *conn = chan->conn;
    555a:	4c 8b 73 08          	mov    0x8(%rbx),%r14
    555e:	48 c1 e8 04          	shr    $0x4,%rax
    5562:	83 e0 01             	and    $0x1,%eax
		return (super << L2CAP_EXT_CTRL_SUPER_SHIFT) &
    5565:	48 83 f8 01          	cmp    $0x1,%rax
    5569:	19 c0                	sbb    %eax,%eax
    556b:	25 08 00 fe ff       	and    $0xfffe0008,%eax
    5570:	05 00 00 02 00       	add    $0x20000,%eax
		control |= __set_ctrl_super(chan, L2CAP_SUPER_RNR);
    5575:	41 09 c4             	or     %eax,%r12d
	if (chan->state != BT_CONNECTED)
    5578:	80 7b 10 01          	cmpb   $0x1,0x10(%rbx)
    557c:	0f 84 22 02 00 00    	je     57a4 <l2cap_data_channel_sframe+0xce4>
		asm volatile(LOCK_PREFIX "orb %1,%0"
    5582:	f0 80 8b 89 00 00 00 	lock orb $0x1,0x89(%rbx)
    5589:	01 
		(addr[nr / BITS_PER_LONG])) != 0;
    558a:	48 8b 83 88 00 00 00 	mov    0x88(%rbx),%rax
	if (test_bit(CONN_REMOTE_BUSY, &chan->conn_state))
    5591:	a8 10                	test   $0x10,%al
    5593:	74 30                	je     55c5 <l2cap_data_channel_sframe+0xb05>
	return list->next == (struct sk_buff *)list;
    5595:	48 8b 83 b8 02 00 00 	mov    0x2b8(%rbx),%rax
	if (!skb_queue_empty(&chan->tx_q))
    559c:	48 8d 93 b8 02 00 00 	lea    0x2b8(%rbx),%rdx
    55a3:	48 39 d0             	cmp    %rdx,%rax
    55a6:	74 07                	je     55af <l2cap_data_channel_sframe+0xaef>
		chan->tx_send_head = chan->tx_q.next;
    55a8:	48 89 83 b0 02 00 00 	mov    %rax,0x2b0(%rbx)
	chan->next_tx_seq = chan->expected_ack_seq;
    55af:	0f b7 83 9a 00 00 00 	movzwl 0x9a(%rbx),%eax
	ret = l2cap_ertm_send(chan);
    55b6:	48 89 df             	mov    %rbx,%rdi
	chan->next_tx_seq = chan->expected_ack_seq;
    55b9:	66 89 83 98 00 00 00 	mov    %ax,0x98(%rbx)
	ret = l2cap_ertm_send(chan);
    55c0:	e8 8b d4 ff ff       	callq  2a50 <l2cap_ertm_send>
	l2cap_ertm_send(chan);
    55c5:	48 89 df             	mov    %rbx,%rdi
    55c8:	e8 83 d4 ff ff       	callq  2a50 <l2cap_ertm_send>
    55cd:	48 8b 83 88 00 00 00 	mov    0x88(%rbx),%rax
	if (!test_bit(CONN_LOCAL_BUSY, &chan->conn_state) &&
    55d4:	a8 20                	test   $0x20,%al
    55d6:	0f 85 14 f9 ff ff    	jne    4ef0 <l2cap_data_channel_sframe+0x430>
    55dc:	66 83 bb a6 00 00 00 	cmpw   $0x0,0xa6(%rbx)
    55e3:	00 
    55e4:	0f 85 06 f9 ff ff    	jne    4ef0 <l2cap_data_channel_sframe+0x430>
	if (chan->state != BT_CONNECTED)
    55ea:	80 7b 10 01          	cmpb   $0x1,0x10(%rbx)
    55ee:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	struct l2cap_conn *conn = chan->conn;
    55f5:	4c 8b 73 08          	mov    0x8(%rbx),%r14
	if (chan->state != BT_CONNECTED)
    55f9:	0f 85 f1 f8 ff ff    	jne    4ef0 <l2cap_data_channel_sframe+0x430>
    55ff:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    5606:	48 c1 e8 04          	shr    $0x4,%rax
    560a:	83 e0 01             	and    $0x1,%eax
		hlen = L2CAP_EXT_HDR_SIZE;
    560d:	48 83 f8 01          	cmp    $0x1,%rax
    5611:	45 19 c0             	sbb    %r8d,%r8d
    5614:	41 83 e0 fe          	and    $0xfffffffe,%r8d
    5618:	41 83 c0 08          	add    $0x8,%r8d
		hlen += L2CAP_FCS_SIZE;
    561c:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    5620:	41 8d 40 02          	lea    0x2(%r8),%eax
    5624:	44 0f 44 c0          	cmove  %eax,%r8d
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    5628:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 562f <l2cap_data_channel_sframe+0xb6f>
    562f:	0f 85 36 04 00 00    	jne    5a6b <l2cap_data_channel_sframe+0xfab>
	count = min_t(unsigned int, conn->mtu, hlen);
    5635:	45 8b 76 20          	mov    0x20(%r14),%r14d
    5639:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    5640:	45 39 f0             	cmp    %r14d,%r8d
    5643:	45 0f 46 f0          	cmovbe %r8d,%r14d
	control |= __set_sframe(chan);
    5647:	41 83 cc 01          	or     $0x1,%r12d
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    564b:	f0 41 0f ba 37 07    	lock btrl $0x7,(%r15)
    5651:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_FBIT, &chan->conn_state))
    5653:	85 c0                	test   %eax,%eax
    5655:	74 1d                	je     5674 <l2cap_data_channel_sframe+0xbb4>
		(addr[nr / BITS_PER_LONG])) != 0;
    5657:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    565e:	48 c1 e8 04          	shr    $0x4,%rax
    5662:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_FINAL;
    5665:	48 83 f8 01          	cmp    $0x1,%rax
    5669:	19 c0                	sbb    %eax,%eax
    566b:	83 e0 7e             	and    $0x7e,%eax
    566e:	83 c0 02             	add    $0x2,%eax
		control |= __set_ctrl_final(chan);
    5671:	41 09 c4             	or     %eax,%r12d
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    5674:	f0 41 0f ba 37 03    	lock btrl $0x3,(%r15)
    567a:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_PBIT, &chan->conn_state))
    567c:	85 c0                	test   %eax,%eax
    567e:	74 21                	je     56a1 <l2cap_data_channel_sframe+0xbe1>
		(addr[nr / BITS_PER_LONG])) != 0;
    5680:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    5687:	48 c1 e8 04          	shr    $0x4,%rax
    568b:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_POLL;
    568e:	48 83 f8 01          	cmp    $0x1,%rax
    5692:	19 c0                	sbb    %eax,%eax
    5694:	25 10 00 fc ff       	and    $0xfffc0010,%eax
    5699:	05 00 00 04 00       	add    $0x40000,%eax
		control |= __set_ctrl_poll(chan);
    569e:	41 09 c4             	or     %eax,%r12d
	if ((skb = alloc_skb(len + BT_SKB_RESERVE, how))) {
    56a1:	41 8d 7e 08          	lea    0x8(%r14),%edi
	return __alloc_skb(size, priority, 0, NUMA_NO_NODE);
    56a5:	31 d2                	xor    %edx,%edx
    56a7:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    56ac:	be 20 00 00 00       	mov    $0x20,%esi
    56b1:	44 89 45 c8          	mov    %r8d,-0x38(%rbp)
    56b5:	e8 00 00 00 00       	callq  56ba <l2cap_data_channel_sframe+0xbfa>
    56ba:	48 85 c0             	test   %rax,%rax
    56bd:	49 89 c7             	mov    %rax,%r15
    56c0:	0f 84 2a f8 ff ff    	je     4ef0 <l2cap_data_channel_sframe+0x430>
	skb->data += len;
    56c6:	48 83 80 e0 00 00 00 	addq   $0x8,0xe0(%rax)
    56cd:	08 
	skb->tail += len;
    56ce:	83 80 cc 00 00 00 08 	addl   $0x8,0xcc(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    56d5:	be 04 00 00 00       	mov    $0x4,%esi
    56da:	48 89 c7             	mov    %rax,%rdi
		bt_cb(skb)->incoming  = 0;
    56dd:	c6 40 29 00          	movb   $0x0,0x29(%rax)
    56e1:	e8 00 00 00 00       	callq  56e6 <l2cap_data_channel_sframe+0xc26>
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    56e6:	44 8b 45 c8          	mov    -0x38(%rbp),%r8d
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    56ea:	48 89 c1             	mov    %rax,%rcx
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    56ed:	4c 89 ff             	mov    %r15,%rdi
	lh->cid = cpu_to_le16(chan->dcid);
    56f0:	48 89 4d c8          	mov    %rcx,-0x38(%rbp)
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    56f4:	41 83 e8 04          	sub    $0x4,%r8d
    56f8:	66 44 89 00          	mov    %r8w,(%rax)
	lh->cid = cpu_to_le16(chan->dcid);
    56fc:	0f b7 43 1a          	movzwl 0x1a(%rbx),%eax
    5700:	66 89 41 02          	mov    %ax,0x2(%rcx)
    5704:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
    570b:	48 c1 ea 04          	shr    $0x4,%rdx
    570f:	83 e2 01             	and    $0x1,%edx
		return L2CAP_EXT_HDR_SIZE - L2CAP_HDR_SIZE;
    5712:	48 83 fa 01          	cmp    $0x1,%rdx
    5716:	19 d2                	sbb    %edx,%edx
    5718:	83 e2 fe             	and    $0xfffffffe,%edx
    571b:	83 c2 04             	add    $0x4,%edx
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    571e:	0f b6 f2             	movzbl %dl,%esi
    5721:	e8 00 00 00 00       	callq  5726 <l2cap_data_channel_sframe+0xc66>
    5726:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    572d:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
    5731:	83 e2 10             	and    $0x10,%edx
    5734:	0f 84 04 02 00 00    	je     593e <l2cap_data_channel_sframe+0xe7e>
	*((__le32 *)p) = cpu_to_le32(val);
    573a:	44 89 20             	mov    %r12d,(%rax)
	if (chan->fcs == L2CAP_FCS_CRC16) {
    573d:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    5741:	41 8d 56 fe          	lea    -0x2(%r14),%edx
	if (chan->fcs == L2CAP_FCS_CRC16) {
    5745:	0f 85 e5 f6 ff ff    	jne    4e30 <l2cap_data_channel_sframe+0x370>
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    574b:	48 63 d2             	movslq %edx,%rdx
    574e:	48 89 ce             	mov    %rcx,%rsi
    5751:	e9 3c fc ff ff       	jmpq   5392 <l2cap_data_channel_sframe+0x8d2>
    5756:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    575d:	00 00 00 
	asm volatile(LOCK_PREFIX "incl %0"
    5760:	f0 ff 43 14          	lock incl 0x14(%rbx)
    5764:	e9 64 fd ff ff       	jmpq   54cd <l2cap_data_channel_sframe+0xa0d>
    5769:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    5770:	66 44 89 30          	mov    %r14w,(%rax)
    5774:	e9 ad f6 ff ff       	jmpq   4e26 <l2cap_data_channel_sframe+0x366>
    5779:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		return (reqseq << L2CAP_CTRL_REQSEQ_SHIFT) & L2CAP_CTRL_REQSEQ;
    5780:	41 c1 e4 08          	shl    $0x8,%r12d
    5784:	41 81 e4 00 3f 00 00 	and    $0x3f00,%r12d
    578b:	e9 b8 fd ff ff       	jmpq   5548 <l2cap_data_channel_sframe+0xa88>
		control |= __set_ctrl_super(chan, L2CAP_SUPER_RR);
    5790:	41 bc 80 00 00 00    	mov    $0x80,%r12d
    5796:	e9 6f fa ff ff       	jmpq   520a <l2cap_data_channel_sframe+0x74a>
    579b:	f0 ff 43 14          	lock incl 0x14(%rbx)
    579f:	e9 62 f4 ff ff       	jmpq   4c06 <l2cap_data_channel_sframe+0x146>
    57a4:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    57ab:	48 c1 e8 04          	shr    $0x4,%rax
    57af:	83 e0 01             	and    $0x1,%eax
		hlen = L2CAP_EXT_HDR_SIZE;
    57b2:	48 83 f8 01          	cmp    $0x1,%rax
    57b6:	45 19 c0             	sbb    %r8d,%r8d
    57b9:	41 83 e0 fe          	and    $0xfffffffe,%r8d
    57bd:	41 83 c0 08          	add    $0x8,%r8d
		hlen += L2CAP_FCS_SIZE;
    57c1:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    57c5:	41 8d 40 02          	lea    0x2(%r8),%eax
    57c9:	44 0f 44 c0          	cmove  %eax,%r8d
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    57cd:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 57d4 <l2cap_data_channel_sframe+0xd14>
    57d4:	0f 85 69 02 00 00    	jne    5a43 <l2cap_data_channel_sframe+0xf83>
	count = min_t(unsigned int, conn->mtu, hlen);
    57da:	41 8b 46 20          	mov    0x20(%r14),%eax
    57de:	41 39 c0             	cmp    %eax,%r8d
    57e1:	41 0f 46 c0          	cmovbe %r8d,%eax
    57e5:	89 45 c0             	mov    %eax,-0x40(%rbp)
    57e8:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	control |= __set_sframe(chan);
    57ef:	44 89 e0             	mov    %r12d,%eax
    57f2:	83 c8 01             	or     $0x1,%eax
    57f5:	89 45 c8             	mov    %eax,-0x38(%rbp)
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    57f8:	f0 41 0f ba 37 07    	lock btrl $0x7,(%r15)
    57fe:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_FBIT, &chan->conn_state))
    5800:	85 c0                	test   %eax,%eax
    5802:	74 1d                	je     5821 <l2cap_data_channel_sframe+0xd61>
		(addr[nr / BITS_PER_LONG])) != 0;
    5804:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    580b:	48 c1 e8 04          	shr    $0x4,%rax
    580f:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_FINAL;
    5812:	48 83 f8 01          	cmp    $0x1,%rax
    5816:	19 c0                	sbb    %eax,%eax
    5818:	83 e0 7e             	and    $0x7e,%eax
    581b:	83 c0 02             	add    $0x2,%eax
		control |= __set_ctrl_final(chan);
    581e:	09 45 c8             	or     %eax,-0x38(%rbp)
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    5821:	f0 41 0f ba 37 03    	lock btrl $0x3,(%r15)
    5827:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_PBIT, &chan->conn_state))
    5829:	85 c0                	test   %eax,%eax
    582b:	74 21                	je     584e <l2cap_data_channel_sframe+0xd8e>
		(addr[nr / BITS_PER_LONG])) != 0;
    582d:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    5834:	48 c1 e8 04          	shr    $0x4,%rax
    5838:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_POLL;
    583b:	48 83 f8 01          	cmp    $0x1,%rax
    583f:	19 c0                	sbb    %eax,%eax
    5841:	25 10 00 fc ff       	and    $0xfffc0010,%eax
    5846:	05 00 00 04 00       	add    $0x40000,%eax
		control |= __set_ctrl_poll(chan);
    584b:	09 45 c8             	or     %eax,-0x38(%rbp)
	if ((skb = alloc_skb(len + BT_SKB_RESERVE, how))) {
    584e:	8b 45 c0             	mov    -0x40(%rbp),%eax
	return __alloc_skb(size, priority, 0, NUMA_NO_NODE);
    5851:	31 d2                	xor    %edx,%edx
    5853:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    5858:	be 20 00 00 00       	mov    $0x20,%esi
    585d:	44 89 45 b8          	mov    %r8d,-0x48(%rbp)
    5861:	8d 78 08             	lea    0x8(%rax),%edi
    5864:	e8 00 00 00 00       	callq  5869 <l2cap_data_channel_sframe+0xda9>
    5869:	48 85 c0             	test   %rax,%rax
    586c:	49 89 c6             	mov    %rax,%r14
    586f:	0f 84 0d fd ff ff    	je     5582 <l2cap_data_channel_sframe+0xac2>
	skb->data += len;
    5875:	48 83 80 e0 00 00 00 	addq   $0x8,0xe0(%rax)
    587c:	08 
	skb->tail += len;
    587d:	83 80 cc 00 00 00 08 	addl   $0x8,0xcc(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    5884:	be 04 00 00 00       	mov    $0x4,%esi
    5889:	48 89 c7             	mov    %rax,%rdi
		bt_cb(skb)->incoming  = 0;
    588c:	c6 40 29 00          	movb   $0x0,0x29(%rax)
    5890:	e8 00 00 00 00       	callq  5895 <l2cap_data_channel_sframe+0xdd5>
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    5895:	44 8b 45 b8          	mov    -0x48(%rbp),%r8d
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    5899:	49 89 c2             	mov    %rax,%r10
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    589c:	4c 89 f7             	mov    %r14,%rdi
	lh->cid = cpu_to_le16(chan->dcid);
    589f:	4c 89 55 b8          	mov    %r10,-0x48(%rbp)
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    58a3:	41 83 e8 04          	sub    $0x4,%r8d
    58a7:	66 44 89 00          	mov    %r8w,(%rax)
	lh->cid = cpu_to_le16(chan->dcid);
    58ab:	0f b7 43 1a          	movzwl 0x1a(%rbx),%eax
    58af:	66 41 89 42 02       	mov    %ax,0x2(%r10)
    58b4:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    58bb:	48 c1 e8 04          	shr    $0x4,%rax
    58bf:	83 e0 01             	and    $0x1,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    58c2:	48 83 f8 01          	cmp    $0x1,%rax
    58c6:	19 f6                	sbb    %esi,%esi
    58c8:	83 e6 fe             	and    $0xfffffffe,%esi
    58cb:	83 c6 04             	add    $0x4,%esi
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    58ce:	e8 00 00 00 00       	callq  58d3 <l2cap_data_channel_sframe+0xe13>
    58d3:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    58da:	4c 8b 55 b8          	mov    -0x48(%rbp),%r10
    58de:	83 e2 10             	and    $0x10,%edx
    58e1:	74 52                	je     5935 <l2cap_data_channel_sframe+0xe75>
    58e3:	8b 4d c8             	mov    -0x38(%rbp),%ecx
    58e6:	89 08                	mov    %ecx,(%rax)
	if (chan->fcs == L2CAP_FCS_CRC16) {
    58e8:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    58ec:	74 7c                	je     596a <l2cap_data_channel_sframe+0xeaa>
	skb->priority = HCI_PRIO_MAX;
    58ee:	41 c7 46 78 07 00 00 	movl   $0x7,0x78(%r14)
    58f5:	00 
	l2cap_do_send(chan, skb);
    58f6:	4c 89 f6             	mov    %r14,%rsi
    58f9:	48 89 df             	mov    %rbx,%rdi
    58fc:	e8 ff ab ff ff       	callq  500 <l2cap_do_send>
    5901:	e9 7c fc ff ff       	jmpq   5582 <l2cap_data_channel_sframe+0xac2>
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    5906:	8b 55 c8             	mov    -0x38(%rbp),%edx
    5909:	83 ea 02             	sub    $0x2,%edx
    590c:	e9 3a fe ff ff       	jmpq   574b <l2cap_data_channel_sframe+0xc8b>
		kfree(c);
    5911:	48 89 df             	mov    %rbx,%rdi
    5914:	e8 00 00 00 00       	callq  5919 <l2cap_data_channel_sframe+0xe59>
    5919:	e9 45 fb ff ff       	jmpq   5463 <l2cap_data_channel_sframe+0x9a3>
    591e:	f0 ff 43 14          	lock incl 0x14(%rbx)
    5922:	e9 f3 fa ff ff       	jmpq   541a <l2cap_data_channel_sframe+0x95a>
    5927:	66 44 89 20          	mov    %r12w,(%rax)
    592b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    5930:	e9 49 fa ff ff       	jmpq   537e <l2cap_data_channel_sframe+0x8be>
    5935:	0f b7 4d c8          	movzwl -0x38(%rbp),%ecx
    5939:	66 89 08             	mov    %cx,(%rax)
    593c:	eb aa                	jmp    58e8 <l2cap_data_channel_sframe+0xe28>
    593e:	66 44 89 20          	mov    %r12w,(%rax)
    5942:	e9 f6 fd ff ff       	jmpq   573d <l2cap_data_channel_sframe+0xc7d>
	BT_DBG("chan %p rx_control 0x%8.8x len %d", chan, rx_control, skb->len);
    5947:	44 8b 42 68          	mov    0x68(%rdx),%r8d
    594b:	89 f1                	mov    %esi,%ecx
    594d:	48 89 fa             	mov    %rdi,%rdx
    5950:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    5957:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    595e:	31 c0                	xor    %eax,%eax
    5960:	e8 00 00 00 00       	callq  5965 <l2cap_data_channel_sframe+0xea5>
    5965:	e9 7d f1 ff ff       	jmpq   4ae7 <l2cap_data_channel_sframe+0x27>
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    596a:	8b 55 c0             	mov    -0x40(%rbp),%edx
    596d:	4c 89 d6             	mov    %r10,%rsi
    5970:	31 ff                	xor    %edi,%edi
    5972:	83 ea 02             	sub    $0x2,%edx
    5975:	48 63 d2             	movslq %edx,%rdx
    5978:	e8 00 00 00 00       	callq  597d <l2cap_data_channel_sframe+0xebd>
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    597d:	be 02 00 00 00       	mov    $0x2,%esi
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    5982:	89 c2                	mov    %eax,%edx
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    5984:	4c 89 f7             	mov    %r14,%rdi
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    5987:	89 55 c8             	mov    %edx,-0x38(%rbp)
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    598a:	e8 00 00 00 00       	callq  598f <l2cap_data_channel_sframe+0xecf>
	*((__le16 *)p) = cpu_to_le16(val);
    598f:	8b 55 c8             	mov    -0x38(%rbp),%edx
    5992:	66 89 10             	mov    %dx,(%rax)
    5995:	e9 54 ff ff ff       	jmpq   58ee <l2cap_data_channel_sframe+0xe2e>
    599a:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    59a1:	a8 10                	test   $0x10,%al
		return (ctrl & L2CAP_EXT_CTRL_REQSEQ) >>
    59a3:	44 89 e0             	mov    %r12d,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    59a6:	0f 84 df 01 00 00    	je     5b8b <l2cap_data_channel_sframe+0x10cb>
		return (ctrl & L2CAP_EXT_CTRL_REQSEQ) >>
    59ac:	25 fc ff 00 00       	and    $0xfffc,%eax
    59b1:	c1 e8 02             	shr    $0x2,%eax
	BT_DBG("chan %p, req_seq %d ctrl 0x%8.8x", chan,
    59b4:	0f b7 c8             	movzwl %ax,%ecx
    59b7:	45 89 e0             	mov    %r12d,%r8d
    59ba:	48 89 da             	mov    %rbx,%rdx
    59bd:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    59c4:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    59cb:	31 c0                	xor    %eax,%eax
    59cd:	e8 00 00 00 00       	callq  59d2 <l2cap_data_channel_sframe+0xf12>
    59d2:	e9 80 f1 ff ff       	jmpq   4b57 <l2cap_data_channel_sframe+0x97>
	BT_DBG("chan %p, req_seq %d ctrl 0x%8.8x", chan, tx_seq, rx_control);
    59d7:	41 0f b7 ce          	movzwl %r14w,%ecx
    59db:	45 89 e0             	mov    %r12d,%r8d
    59de:	48 89 da             	mov    %rbx,%rdx
    59e1:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    59e8:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    59ef:	31 c0                	xor    %eax,%eax
    59f1:	e8 00 00 00 00       	callq  59f6 <l2cap_data_channel_sframe+0xf36>
    59f6:	e9 7f f4 ff ff       	jmpq   4e7a <l2cap_data_channel_sframe+0x3ba>
	BT_DBG("chan %p, req_seq %d ctrl 0x%8.8x", chan, tx_seq, rx_control);
    59fb:	41 0f b7 ce          	movzwl %r14w,%ecx
    59ff:	45 89 e0             	mov    %r12d,%r8d
    5a02:	48 89 da             	mov    %rbx,%rdx
    5a05:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    5a0c:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    5a13:	31 c0                	xor    %eax,%eax
    5a15:	e8 00 00 00 00       	callq  5a1a <l2cap_data_channel_sframe+0xf5a>
    5a1a:	e9 1b f5 ff ff       	jmpq   4f3a <l2cap_data_channel_sframe+0x47a>
	BT_DBG("chan %p, req_seq %d ctrl 0x%8.8x", chan, tx_seq, rx_control);
    5a1f:	41 0f b7 ce          	movzwl %r14w,%ecx
    5a23:	45 89 e0             	mov    %r12d,%r8d
    5a26:	48 89 da             	mov    %rbx,%rdx
    5a29:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    5a30:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    5a37:	31 c0                	xor    %eax,%eax
    5a39:	e8 00 00 00 00       	callq  5a3e <l2cap_data_channel_sframe+0xf7e>
    5a3e:	e9 2d f2 ff ff       	jmpq   4c70 <l2cap_data_channel_sframe+0x1b0>
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    5a43:	44 89 e1             	mov    %r12d,%ecx
    5a46:	48 89 da             	mov    %rbx,%rdx
    5a49:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    5a50:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    5a57:	31 c0                	xor    %eax,%eax
    5a59:	44 89 45 c8          	mov    %r8d,-0x38(%rbp)
    5a5d:	e8 00 00 00 00       	callq  5a62 <l2cap_data_channel_sframe+0xfa2>
    5a62:	44 8b 45 c8          	mov    -0x38(%rbp),%r8d
    5a66:	e9 6f fd ff ff       	jmpq   57da <l2cap_data_channel_sframe+0xd1a>
    5a6b:	44 89 e1             	mov    %r12d,%ecx
    5a6e:	48 89 da             	mov    %rbx,%rdx
    5a71:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    5a78:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    5a7f:	31 c0                	xor    %eax,%eax
    5a81:	44 89 45 c8          	mov    %r8d,-0x38(%rbp)
    5a85:	e8 00 00 00 00       	callq  5a8a <l2cap_data_channel_sframe+0xfca>
    5a8a:	44 8b 45 c8          	mov    -0x38(%rbp),%r8d
    5a8e:	e9 a2 fb ff ff       	jmpq   5635 <l2cap_data_channel_sframe+0xb75>
	switch (state) {
    5a93:	0f b6 43 10          	movzbl 0x10(%rbx),%eax
    5a97:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    5a9e:	83 e8 01             	sub    $0x1,%eax
    5aa1:	83 f8 08             	cmp    $0x8,%eax
    5aa4:	77 08                	ja     5aae <l2cap_data_channel_sframe+0xfee>
    5aa6:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    5aad:	00 
	BT_DBG("chan %p state %s timeout %ld", chan,
    5aae:	4d 89 e0             	mov    %r12,%r8
    5ab1:	48 89 da             	mov    %rbx,%rdx
    5ab4:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    5abb:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    5ac2:	31 c0                	xor    %eax,%eax
    5ac4:	e8 00 00 00 00       	callq  5ac9 <l2cap_data_channel_sframe+0x1009>
    5ac9:	e9 1c f1 ff ff       	jmpq   4bea <l2cap_data_channel_sframe+0x12a>
    5ace:	44 89 e1             	mov    %r12d,%ecx
    5ad1:	48 89 da             	mov    %rbx,%rdx
    5ad4:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    5adb:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    5ae2:	31 c0                	xor    %eax,%eax
    5ae4:	44 89 4d c8          	mov    %r9d,-0x38(%rbp)
    5ae8:	e8 00 00 00 00       	callq  5aed <l2cap_data_channel_sframe+0x102d>
    5aed:	44 8b 4d c8          	mov    -0x38(%rbp),%r9d
    5af1:	e9 82 f7 ff ff       	jmpq   5278 <l2cap_data_channel_sframe+0x7b8>
    5af6:	31 c9                	xor    %ecx,%ecx
    5af8:	48 89 da             	mov    %rbx,%rdx
    5afb:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    5b02:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    5b09:	31 c0                	xor    %eax,%eax
    5b0b:	e8 00 00 00 00       	callq  5b10 <l2cap_data_channel_sframe+0x1050>
    5b10:	e9 0c f2 ff ff       	jmpq   4d21 <l2cap_data_channel_sframe+0x261>
    5b15:	0f b6 43 10          	movzbl 0x10(%rbx),%eax
    5b19:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    5b20:	83 e8 01             	sub    $0x1,%eax
    5b23:	83 f8 08             	cmp    $0x8,%eax
    5b26:	77 08                	ja     5b30 <l2cap_data_channel_sframe+0x1070>
    5b28:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    5b2f:	00 
    5b30:	4d 89 f0             	mov    %r14,%r8
    5b33:	48 89 da             	mov    %rbx,%rdx
    5b36:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    5b3d:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    5b44:	31 c0                	xor    %eax,%eax
    5b46:	e8 00 00 00 00       	callq  5b4b <l2cap_data_channel_sframe+0x108b>
    5b4b:	e9 61 f9 ff ff       	jmpq   54b1 <l2cap_data_channel_sframe+0x9f1>
    5b50:	0f b6 43 10          	movzbl 0x10(%rbx),%eax
    5b54:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    5b5b:	83 e8 01             	sub    $0x1,%eax
    5b5e:	83 f8 08             	cmp    $0x8,%eax
    5b61:	77 08                	ja     5b6b <l2cap_data_channel_sframe+0x10ab>
    5b63:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    5b6a:	00 
    5b6b:	4d 89 e0             	mov    %r12,%r8
    5b6e:	48 89 da             	mov    %rbx,%rdx
    5b71:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    5b78:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    5b7f:	31 c0                	xor    %eax,%eax
    5b81:	e8 00 00 00 00       	callq  5b86 <l2cap_data_channel_sframe+0x10c6>
    5b86:	e9 73 f8 ff ff       	jmpq   53fe <l2cap_data_channel_sframe+0x93e>
		return (ctrl & L2CAP_CTRL_REQSEQ) >> L2CAP_CTRL_REQSEQ_SHIFT;
    5b8b:	25 00 3f 00 00       	and    $0x3f00,%eax
    5b90:	c1 e8 08             	shr    $0x8,%eax
    5b93:	e9 1c fe ff ff       	jmpq   59b4 <l2cap_data_channel_sframe+0xef4>
    5b98:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    5b9f:	00 

0000000000005ba0 <l2cap_ertm_data_rcv>:
{
    5ba0:	55                   	push   %rbp
    5ba1:	48 89 e5             	mov    %rsp,%rbp
    5ba4:	41 57                	push   %r15
    5ba6:	41 56                	push   %r14
    5ba8:	41 55                	push   %r13
    5baa:	41 54                	push   %r12
    5bac:	53                   	push   %rbx
    5bad:	48 83 ec 28          	sub    $0x28,%rsp
    5bb1:	e8 00 00 00 00       	callq  5bb6 <l2cap_ertm_data_rcv+0x16>
    5bb6:	48 8b 87 90 00 00 00 	mov    0x90(%rdi),%rax
		__unpack_extended_control(get_unaligned_le32(skb->data),
    5bbd:	48 8b 8e e0 00 00 00 	mov    0xe0(%rsi),%rcx
{
    5bc4:	49 89 fd             	mov    %rdi,%r13
    5bc7:	49 89 f4             	mov    %rsi,%r12
	if (test_bit(FLAG_EXT_CTRL, &chan->flags)) {
    5bca:	a8 10                	test   $0x10,%al
    5bcc:	0f 85 b6 03 00 00    	jne    5f88 <l2cap_ertm_data_rcv+0x3e8>
static inline u16 get_unaligned_le16(const void *p)
    5bd2:	0f b7 11             	movzwl (%rcx),%edx
	control->reqseq = (enh & L2CAP_CTRL_REQSEQ) >> L2CAP_CTRL_REQSEQ_SHIFT;
    5bd5:	89 d0                	mov    %edx,%eax
    5bd7:	25 00 3f 00 00       	and    $0x3f00,%eax
    5bdc:	c1 f8 08             	sar    $0x8,%eax
    5bdf:	66 89 46 32          	mov    %ax,0x32(%rsi)
	control->final = (enh & L2CAP_CTRL_FINAL) >> L2CAP_CTRL_FINAL_SHIFT;
    5be3:	41 0f b6 44 24 30    	movzbl 0x30(%r12),%eax
    5be9:	89 d6                	mov    %edx,%esi
    5beb:	c1 ee 07             	shr    $0x7,%esi
    5bee:	83 e6 01             	and    $0x1,%esi
    5bf1:	c1 e6 02             	shl    $0x2,%esi
    5bf4:	83 e0 fb             	and    $0xfffffffb,%eax
    5bf7:	09 f0                	or     %esi,%eax
	if (enh & L2CAP_CTRL_FRAME_TYPE) {
    5bf9:	f6 c2 01             	test   $0x1,%dl
	control->final = (enh & L2CAP_CTRL_FINAL) >> L2CAP_CTRL_FINAL_SHIFT;
    5bfc:	41 88 44 24 30       	mov    %al,0x30(%r12)
	if (enh & L2CAP_CTRL_FRAME_TYPE) {
    5c01:	0f 85 a9 02 00 00    	jne    5eb0 <l2cap_ertm_data_rcv+0x310>
		control->sar = (enh & L2CAP_CTRL_SAR) >> L2CAP_CTRL_SAR_SHIFT;
    5c07:	89 d3                	mov    %edx,%ebx
    5c09:	83 e0 0c             	and    $0xc,%eax
		control->txseq = (enh & L2CAP_CTRL_TXSEQ) >> L2CAP_CTRL_TXSEQ_SHIFT;
    5c0c:	83 e2 7e             	and    $0x7e,%edx
		control->sar = (enh & L2CAP_CTRL_SAR) >> L2CAP_CTRL_SAR_SHIFT;
    5c0f:	66 c1 eb 0e          	shr    $0xe,%bx
		control->txseq = (enh & L2CAP_CTRL_TXSEQ) >> L2CAP_CTRL_TXSEQ_SHIFT;
    5c13:	d1 fa                	sar    %edx
		control->sar = (enh & L2CAP_CTRL_SAR) >> L2CAP_CTRL_SAR_SHIFT;
    5c15:	89 de                	mov    %ebx,%esi
		control->txseq = (enh & L2CAP_CTRL_TXSEQ) >> L2CAP_CTRL_TXSEQ_SHIFT;
    5c17:	66 41 89 54 24 34    	mov    %dx,0x34(%r12)
		control->sar = (enh & L2CAP_CTRL_SAR) >> L2CAP_CTRL_SAR_SHIFT;
    5c1d:	c1 e6 04             	shl    $0x4,%esi
		control->super = 0;
    5c20:	09 f0                	or     %esi,%eax
    5c22:	41 88 44 24 30       	mov    %al,0x30(%r12)
    5c27:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    5c2e:	a8 10                	test   $0x10,%al
    5c30:	0f 84 b3 02 00 00    	je     5ee9 <l2cap_ertm_data_rcv+0x349>
static inline u32 get_unaligned_le32(const void *p)
    5c36:	44 8b 39             	mov    (%rcx),%r15d
    5c39:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
	skb_pull(skb, __ctrl_size(chan));
    5c40:	4c 89 e7             	mov    %r12,%rdi
    5c43:	48 c1 e8 04          	shr    $0x4,%rax
    5c47:	83 e0 01             	and    $0x1,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    5c4a:	48 83 f8 01          	cmp    $0x1,%rax
    5c4e:	19 f6                	sbb    %esi,%esi
    5c50:	83 e6 fe             	and    $0xfffffffe,%esi
    5c53:	83 c6 04             	add    $0x4,%esi
    5c56:	e8 00 00 00 00       	callq  5c5b <l2cap_ertm_data_rcv+0xbb>
	if (l2cap_check_fcs(chan, skb))
    5c5b:	4c 89 e6             	mov    %r12,%rsi
    5c5e:	4c 89 ef             	mov    %r13,%rdi
	len = skb->len;
    5c61:	41 8b 5c 24 68       	mov    0x68(%r12),%ebx
	if (l2cap_check_fcs(chan, skb))
    5c66:	e8 65 ae ff ff       	callq  ad0 <l2cap_check_fcs>
    5c6b:	85 c0                	test   %eax,%eax
    5c6d:	0f 85 c5 02 00 00    	jne    5f38 <l2cap_ertm_data_rcv+0x398>
    5c73:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    5c7a:	a8 10                	test   $0x10,%al
		return (ctrl & L2CAP_EXT_CTRL_SAR) >> L2CAP_EXT_CTRL_SAR_SHIFT;
    5c7c:	44 89 f8             	mov    %r15d,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    5c7f:	0f 84 5b 03 00 00    	je     5fe0 <l2cap_ertm_data_rcv+0x440>
		return (ctrl & L2CAP_EXT_CTRL_SAR) >> L2CAP_EXT_CTRL_SAR_SHIFT;
    5c85:	25 00 00 03 00       	and    $0x30000,%eax
	len = skb->len;
    5c8a:	89 de                	mov    %ebx,%esi
    5c8c:	c1 e8 10             	shr    $0x10,%eax
	if (__is_sar_start(chan, control) && !__is_sframe(chan, control))
    5c8f:	3c 01                	cmp    $0x1,%al
    5c91:	0f 84 5b 03 00 00    	je     5ff2 <l2cap_ertm_data_rcv+0x452>
		len -= L2CAP_FCS_SIZE;
    5c97:	41 80 7d 6f 01       	cmpb   $0x1,0x6f(%r13)
    5c9c:	8d 46 fe             	lea    -0x2(%rsi),%eax
    5c9f:	0f 44 f0             	cmove  %eax,%esi
	if (len > chan->mps) {
    5ca2:	41 0f b7 45 7a       	movzwl 0x7a(%r13),%eax
    5ca7:	39 c6                	cmp    %eax,%esi
    5ca9:	0f 8f c1 02 00 00    	jg     5f70 <l2cap_ertm_data_rcv+0x3d0>
    5caf:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
		return (ctrl & L2CAP_EXT_CTRL_REQSEQ) >>
    5cb6:	44 89 fa             	mov    %r15d,%edx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    5cb9:	a8 10                	test   $0x10,%al
    5cbb:	0f 84 7f 03 00 00    	je     6040 <l2cap_ertm_data_rcv+0x4a0>
		return (ctrl & L2CAP_EXT_CTRL_REQSEQ) >>
    5cc1:	81 e2 fc ff 00 00    	and    $0xfffc,%edx
    5cc7:	c1 ea 02             	shr    $0x2,%edx
	req_seq_offset = __seq_offset(chan, req_seq, chan->expected_ack_seq);
    5cca:	41 0f b7 85 9a 00 00 	movzwl 0x9a(%r13),%eax
    5cd1:	00 
	if (seq1 >= seq2)
    5cd2:	66 39 d0             	cmp    %dx,%ax
		return seq1 - seq2;
    5cd5:	0f b7 f8             	movzwl %ax,%edi
	if (seq1 >= seq2)
    5cd8:	0f 87 4a 03 00 00    	ja     6028 <l2cap_ertm_data_rcv+0x488>
		return seq1 - seq2;
    5cde:	0f b7 d2             	movzwl %dx,%edx
    5ce1:	29 fa                	sub    %edi,%edx
	next_tx_seq_offset = __seq_offset(chan, chan->next_tx_seq,
    5ce3:	41 0f b7 8d 98 00 00 	movzwl 0x98(%r13),%ecx
    5cea:	00 
	if (seq1 >= seq2)
    5ceb:	66 39 c8             	cmp    %cx,%ax
    5cee:	0f 87 1c 03 00 00    	ja     6010 <l2cap_ertm_data_rcv+0x470>
		return seq1 - seq2;
    5cf4:	0f b7 c1             	movzwl %cx,%eax
    5cf7:	29 f8                	sub    %edi,%eax
	if (req_seq_offset > next_tx_seq_offset) {
    5cf9:	39 c2                	cmp    %eax,%edx
    5cfb:	0f 8f 6f 02 00 00    	jg     5f70 <l2cap_ertm_data_rcv+0x3d0>
    5d01:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
		return ctrl & L2CAP_CTRL_FRAME_TYPE;
    5d08:	44 89 f8             	mov    %r15d,%eax
    5d0b:	83 e0 01             	and    $0x1,%eax
	if (!__is_sframe(chan, control)) {
    5d0e:	84 c0                	test   %al,%al
    5d10:	0f 85 42 02 00 00    	jne    5f58 <l2cap_ertm_data_rcv+0x3b8>
		if (len < 0) {
    5d16:	85 f6                	test   %esi,%esi
    5d18:	0f 88 52 02 00 00    	js     5f70 <l2cap_ertm_data_rcv+0x3d0>
    5d1e:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    5d25:	a8 10                	test   $0x10,%al
    5d27:	0f 84 5b 03 00 00    	je     6088 <l2cap_ertm_data_rcv+0x4e8>
		return (ctrl & L2CAP_EXT_CTRL_TXSEQ) >>
    5d2d:	44 89 f8             	mov    %r15d,%eax
    5d30:	c1 e8 12             	shr    $0x12,%eax
    5d33:	89 c3                	mov    %eax,%ebx
    5d35:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
		return (ctrl & L2CAP_EXT_CTRL_REQSEQ) >>
    5d3c:	45 89 fb             	mov    %r15d,%r11d
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    5d3f:	a8 10                	test   $0x10,%al
    5d41:	0f 84 69 03 00 00    	je     60b0 <l2cap_ertm_data_rcv+0x510>
		return (ctrl & L2CAP_EXT_CTRL_REQSEQ) >>
    5d47:	41 81 e3 fc ff 00 00 	and    $0xfffc,%r11d
    5d4e:	41 c1 eb 02          	shr    $0x2,%r11d
    5d52:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    5d59:	a8 10                	test   $0x10,%al
		return (ctrl & L2CAP_EXT_CTRL_SAR) >> L2CAP_EXT_CTRL_SAR_SHIFT;
    5d5b:	44 89 f8             	mov    %r15d,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    5d5e:	0f 84 34 03 00 00    	je     6098 <l2cap_ertm_data_rcv+0x4f8>
		return (ctrl & L2CAP_EXT_CTRL_SAR) >> L2CAP_EXT_CTRL_SAR_SHIFT;
    5d64:	25 00 00 03 00       	and    $0x30000,%eax
    5d69:	c1 e8 10             	shr    $0x10,%eax
    5d6c:	89 45 c8             	mov    %eax,-0x38(%rbp)
	int num_to_ack = (chan->tx_win/6) + 1;
    5d6f:	41 0f b7 45 70       	movzwl 0x70(%r13),%eax
	BT_DBG("chan %p len %d tx_seq %d rx_control 0x%8.8x", chan, skb->len,
    5d74:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 5d7b <l2cap_ertm_data_rcv+0x1db>
	int num_to_ack = (chan->tx_win/6) + 1;
    5d7b:	66 89 45 c6          	mov    %ax,-0x3a(%rbp)
	BT_DBG("chan %p len %d tx_seq %d rx_control 0x%8.8x", chan, skb->len,
    5d7f:	0f 85 5b 0b 00 00    	jne    68e0 <l2cap_ertm_data_rcv+0xd40>
    5d85:	44 0f b7 f3          	movzwl %bx,%r14d
    5d89:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    5d90:	a8 10                	test   $0x10,%al
		return ctrl & L2CAP_EXT_CTRL_FINAL;
    5d92:	44 89 f8             	mov    %r15d,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    5d95:	0f 84 25 03 00 00    	je     60c0 <l2cap_ertm_data_rcv+0x520>
		return ctrl & L2CAP_EXT_CTRL_FINAL;
    5d9b:	d1 e8                	shr    %eax
    5d9d:	83 e0 01             	and    $0x1,%eax
	if (__is_ctrl_final(chan, rx_control) &&
    5da0:	84 c0                	test   %al,%al
    5da2:	74 0f                	je     5db3 <l2cap_ertm_data_rcv+0x213>
    5da4:	49 8b 85 88 00 00 00 	mov    0x88(%r13),%rax
    5dab:	a8 02                	test   $0x2,%al
    5dad:	0f 85 31 03 00 00    	jne    60e4 <l2cap_ertm_data_rcv+0x544>
	chan->expected_ack_seq = req_seq;
    5db3:	66 45 89 9d 9a 00 00 	mov    %r11w,0x9a(%r13)
    5dba:	00 
	l2cap_drop_acked_frames(chan);
    5dbb:	4c 89 ef             	mov    %r13,%rdi
    5dbe:	e8 6d c7 ff ff       	callq  2530 <l2cap_drop_acked_frames>
	tx_seq_offset = __seq_offset(chan, tx_seq, chan->buffer_seq);
    5dc3:	41 0f b7 85 9e 00 00 	movzwl 0x9e(%r13),%eax
    5dca:	00 
	if (seq1 >= seq2)
    5dcb:	66 39 c3             	cmp    %ax,%bx
    5dce:	0f 82 fc 02 00 00    	jb     60d0 <l2cap_ertm_data_rcv+0x530>
		return seq1 - seq2;
    5dd4:	0f b7 c8             	movzwl %ax,%ecx
    5dd7:	44 89 f2             	mov    %r14d,%edx
    5dda:	29 ca                	sub    %ecx,%edx
	if (tx_seq_offset >= chan->tx_win) {
    5ddc:	41 0f b7 75 70       	movzwl 0x70(%r13),%esi
    5de1:	39 d6                	cmp    %edx,%esi
    5de3:	0f 8e 87 01 00 00    	jle    5f70 <l2cap_ertm_data_rcv+0x3d0>
    5de9:	49 8b b5 88 00 00 00 	mov    0x88(%r13),%rsi
	if (test_bit(CONN_LOCAL_BUSY, &chan->conn_state)) {
    5df0:	83 e6 20             	and    $0x20,%esi
    5df3:	0f 85 ff 00 00 00    	jne    5ef8 <l2cap_ertm_data_rcv+0x358>
	if (tx_seq == chan->expected_tx_seq)
    5df9:	41 0f b7 b5 9c 00 00 	movzwl 0x9c(%r13),%esi
    5e00:	00 
    5e01:	66 39 f3             	cmp    %si,%bx
    5e04:	0f 84 eb 03 00 00    	je     61f5 <l2cap_ertm_data_rcv+0x655>
    5e0a:	49 8b bd 88 00 00 00 	mov    0x88(%r13),%rdi
	if (test_bit(CONN_SREJ_SENT, &chan->conn_state)) {
    5e11:	83 e7 01             	and    $0x1,%edi
    5e14:	0f 84 18 03 00 00    	je     6132 <l2cap_ertm_data_rcv+0x592>
		first = list_first_entry(&chan->srej_l,
    5e1a:	4d 8b bd 08 03 00 00 	mov    0x308(%r13),%r15
			l2cap_add_to_srej_queue(chan, skb, tx_seq, sar);
    5e21:	0f b6 4d c8          	movzbl -0x38(%rbp),%ecx
    5e25:	44 89 f2             	mov    %r14d,%edx
    5e28:	4c 89 e6             	mov    %r12,%rsi
    5e2b:	4c 89 ef             	mov    %r13,%rdi
		if (tx_seq == first->tx_seq) {
    5e2e:	66 41 3b 5f f8       	cmp    -0x8(%r15),%bx
    5e33:	0f 84 bc 05 00 00    	je     63f5 <l2cap_ertm_data_rcv+0x855>
			if (l2cap_add_to_srej_queue(chan, skb, tx_seq, sar) < 0)
    5e39:	e8 82 eb ff ff       	callq  49c0 <l2cap_add_to_srej_queue>
    5e3e:	85 c0                	test   %eax,%eax
    5e40:	0f 88 f2 00 00 00    	js     5f38 <l2cap_ertm_data_rcv+0x398>
			list_for_each_entry(l, &chan->srej_l, list) {
    5e46:	49 8b 8d 08 03 00 00 	mov    0x308(%r13),%rcx
    5e4d:	4d 8d a5 08 03 00 00 	lea    0x308(%r13),%r12
    5e54:	4c 39 e1             	cmp    %r12,%rcx
    5e57:	4c 8d 79 f8          	lea    -0x8(%rcx),%r15
    5e5b:	48 89 cf             	mov    %rcx,%rdi
    5e5e:	74 27                	je     5e87 <l2cap_ertm_data_rcv+0x2e7>
				if (l->tx_seq == tx_seq) {
    5e60:	0f b7 51 f8          	movzwl -0x8(%rcx),%edx
    5e64:	66 39 d3             	cmp    %dx,%bx
    5e67:	75 11                	jne    5e7a <l2cap_ertm_data_rcv+0x2da>
    5e69:	e9 2c 09 00 00       	jmpq   679a <l2cap_ertm_data_rcv+0xbfa>
    5e6e:	66 90                	xchg   %ax,%ax
    5e70:	66 3b 58 f8          	cmp    -0x8(%rax),%bx
    5e74:	0f 84 d6 06 00 00    	je     6550 <l2cap_ertm_data_rcv+0x9b0>
			list_for_each_entry(l, &chan->srej_l, list) {
    5e7a:	49 8b 47 08          	mov    0x8(%r15),%rax
    5e7e:	49 39 c4             	cmp    %rax,%r12
    5e81:	4c 8d 78 f8          	lea    -0x8(%rax),%r15
    5e85:	75 e9                	jne    5e70 <l2cap_ertm_data_rcv+0x2d0>
		err = l2cap_send_srejframe(chan, tx_seq);
    5e87:	44 89 f6             	mov    %r14d,%esi
    5e8a:	4c 89 ef             	mov    %r13,%rdi
    5e8d:	e8 fe d1 ff ff       	callq  3090 <l2cap_send_srejframe>
		if (err < 0) {
    5e92:	85 c0                	test   %eax,%eax
    5e94:	0f 89 a6 00 00 00    	jns    5f40 <l2cap_ertm_data_rcv+0x3a0>
			l2cap_send_disconn_req(chan->conn, chan, -err);
    5e9a:	49 8b 7d 08          	mov    0x8(%r13),%rdi
    5e9e:	f7 d8                	neg    %eax
    5ea0:	4c 89 ee             	mov    %r13,%rsi
    5ea3:	89 c2                	mov    %eax,%edx
    5ea5:	e8 56 c7 ff ff       	callq  2600 <l2cap_send_disconn_req>
    5eaa:	e9 91 00 00 00       	jmpq   5f40 <l2cap_ertm_data_rcv+0x3a0>
    5eaf:	90                   	nop
		control->poll = (enh & L2CAP_CTRL_POLL) >> L2CAP_CTRL_POLL_SHIFT;
    5eb0:	89 d6                	mov    %edx,%esi
		control->sframe = 1;
    5eb2:	83 c8 01             	or     $0x1,%eax
		control->super = (enh & L2CAP_CTRL_SUPERVISE) >> L2CAP_CTRL_SUPER_SHIFT;
    5eb5:	c1 e2 04             	shl    $0x4,%edx
		control->poll = (enh & L2CAP_CTRL_POLL) >> L2CAP_CTRL_POLL_SHIFT;
    5eb8:	c1 ee 04             	shr    $0x4,%esi
    5ebb:	83 e0 3d             	and    $0x3d,%eax
    5ebe:	83 e6 01             	and    $0x1,%esi
    5ec1:	01 f6                	add    %esi,%esi
		control->super = (enh & L2CAP_CTRL_SUPERVISE) >> L2CAP_CTRL_SUPER_SHIFT;
    5ec3:	83 e2 c0             	and    $0xffffffc0,%edx
    5ec6:	09 f0                	or     %esi,%eax
    5ec8:	09 d0                	or     %edx,%eax
		control->sar = 0;
    5eca:	83 e0 cf             	and    $0xffffffcf,%eax
    5ecd:	41 88 44 24 30       	mov    %al,0x30(%r12)
		control->txseq = 0;
    5ed2:	31 c0                	xor    %eax,%eax
    5ed4:	66 41 89 44 24 34    	mov    %ax,0x34(%r12)
    5eda:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    5ee1:	a8 10                	test   $0x10,%al
    5ee3:	0f 85 4d fd ff ff    	jne    5c36 <l2cap_ertm_data_rcv+0x96>
		return get_unaligned_le16(p);
    5ee9:	44 0f b7 39          	movzwl (%rcx),%r15d
    5eed:	e9 47 fd ff ff       	jmpq   5c39 <l2cap_ertm_data_rcv+0x99>
    5ef2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    5ef8:	49 8b 85 88 00 00 00 	mov    0x88(%r13),%rax
		if (!test_bit(CONN_RNR_SENT, &chan->conn_state))
    5eff:	f6 c4 01             	test   $0x1,%ah
    5f02:	75 34                	jne    5f38 <l2cap_ertm_data_rcv+0x398>
	ret = del_timer_sync(&work->timer);
    5f04:	49 8d bd 60 02 00 00 	lea    0x260(%r13),%rdi
    5f0b:	e8 00 00 00 00       	callq  5f10 <l2cap_ertm_data_rcv+0x370>
	if (ret)
    5f10:	85 c0                	test   %eax,%eax
    5f12:	74 19                	je     5f2d <l2cap_ertm_data_rcv+0x38d>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    5f14:	f0 41 80 a5 40 02 00 	lock andb $0xfe,0x240(%r13)
    5f1b:	00 fe 
	asm volatile(LOCK_PREFIX "decl %0; sete %1"
    5f1d:	f0 41 ff 4d 14       	lock decl 0x14(%r13)
    5f22:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    5f25:	84 c0                	test   %al,%al
    5f27:	0f 85 7f 08 00 00    	jne    67ac <l2cap_ertm_data_rcv+0xc0c>
	__l2cap_send_ack(chan);
    5f2d:	4c 89 ef             	mov    %r13,%rdi
    5f30:	e8 bb dc ff ff       	callq  3bf0 <__l2cap_send_ack>
    5f35:	0f 1f 00             	nopl   (%rax)
	kfree_skb(skb);
    5f38:	4c 89 e7             	mov    %r12,%rdi
    5f3b:	e8 00 00 00 00       	callq  5f40 <l2cap_ertm_data_rcv+0x3a0>
}
    5f40:	48 83 c4 28          	add    $0x28,%rsp
    5f44:	31 c0                	xor    %eax,%eax
    5f46:	5b                   	pop    %rbx
    5f47:	41 5c                	pop    %r12
    5f49:	41 5d                	pop    %r13
    5f4b:	41 5e                	pop    %r14
    5f4d:	41 5f                	pop    %r15
    5f4f:	5d                   	pop    %rbp
    5f50:	c3                   	retq   
    5f51:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		if (len != 0) {
    5f58:	85 f6                	test   %esi,%esi
    5f5a:	0f 84 10 01 00 00    	je     6070 <l2cap_ertm_data_rcv+0x4d0>
			BT_ERR("%d", len);
    5f60:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    5f67:	31 c0                	xor    %eax,%eax
    5f69:	e8 00 00 00 00       	callq  5f6e <l2cap_ertm_data_rcv+0x3ce>
    5f6e:	66 90                	xchg   %ax,%ax
			l2cap_send_disconn_req(chan->conn, chan, ECONNRESET);
    5f70:	49 8b 7d 08          	mov    0x8(%r13),%rdi
    5f74:	ba 68 00 00 00       	mov    $0x68,%edx
    5f79:	4c 89 ee             	mov    %r13,%rsi
    5f7c:	e8 7f c6 ff ff       	callq  2600 <l2cap_send_disconn_req>
			goto drop;
    5f81:	eb b5                	jmp    5f38 <l2cap_ertm_data_rcv+0x398>
    5f83:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    5f88:	8b 11                	mov    (%rcx),%edx
	control->reqseq = (ext & L2CAP_EXT_CTRL_REQSEQ) >> L2CAP_EXT_CTRL_REQSEQ_SHIFT;
    5f8a:	89 d0                	mov    %edx,%eax
    5f8c:	25 fc ff 00 00       	and    $0xfffc,%eax
    5f91:	c1 e8 02             	shr    $0x2,%eax
    5f94:	66 89 46 32          	mov    %ax,0x32(%rsi)
	control->final = (ext & L2CAP_EXT_CTRL_FINAL) >> L2CAP_EXT_CTRL_FINAL_SHIFT;
    5f98:	41 0f b6 44 24 30    	movzbl 0x30(%r12),%eax
    5f9e:	89 d6                	mov    %edx,%esi
    5fa0:	d1 ee                	shr    %esi
    5fa2:	83 e6 01             	and    $0x1,%esi
    5fa5:	c1 e6 02             	shl    $0x2,%esi
    5fa8:	83 e0 fb             	and    $0xfffffffb,%eax
    5fab:	09 f0                	or     %esi,%eax
	if (ext & L2CAP_EXT_CTRL_FRAME_TYPE) {
    5fad:	f6 c2 01             	test   $0x1,%dl
	control->final = (ext & L2CAP_EXT_CTRL_FINAL) >> L2CAP_EXT_CTRL_FINAL_SHIFT;
    5fb0:	41 88 44 24 30       	mov    %al,0x30(%r12)
	if (ext & L2CAP_EXT_CTRL_FRAME_TYPE) {
    5fb5:	0f 85 95 00 00 00    	jne    6050 <l2cap_ertm_data_rcv+0x4b0>
		control->sar = (ext & L2CAP_EXT_CTRL_SAR) >> L2CAP_EXT_CTRL_SAR_SHIFT;
    5fbb:	89 d6                	mov    %edx,%esi
    5fbd:	83 e0 0c             	and    $0xc,%eax
		control->txseq = (ext & L2CAP_EXT_CTRL_TXSEQ) >> L2CAP_EXT_CTRL_TXSEQ_SHIFT;
    5fc0:	c1 ea 12             	shr    $0x12,%edx
		control->sar = (ext & L2CAP_EXT_CTRL_SAR) >> L2CAP_EXT_CTRL_SAR_SHIFT;
    5fc3:	c1 ee 0c             	shr    $0xc,%esi
		control->txseq = (ext & L2CAP_EXT_CTRL_TXSEQ) >> L2CAP_EXT_CTRL_TXSEQ_SHIFT;
    5fc6:	66 41 89 54 24 34    	mov    %dx,0x34(%r12)
		control->sar = (ext & L2CAP_EXT_CTRL_SAR) >> L2CAP_EXT_CTRL_SAR_SHIFT;
    5fcc:	83 e6 30             	and    $0x30,%esi
		control->super = 0;
    5fcf:	09 f0                	or     %esi,%eax
    5fd1:	41 88 44 24 30       	mov    %al,0x30(%r12)
    5fd6:	e9 4c fc ff ff       	jmpq   5c27 <l2cap_ertm_data_rcv+0x87>
    5fdb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		return (ctrl & L2CAP_CTRL_SAR) >> L2CAP_CTRL_SAR_SHIFT;
    5fe0:	25 00 c0 00 00       	and    $0xc000,%eax
	len = skb->len;
    5fe5:	89 de                	mov    %ebx,%esi
    5fe7:	c1 e8 0e             	shr    $0xe,%eax
	if (__is_sar_start(chan, control) && !__is_sframe(chan, control))
    5fea:	3c 01                	cmp    $0x1,%al
    5fec:	0f 85 a5 fc ff ff    	jne    5c97 <l2cap_ertm_data_rcv+0xf7>
		(addr[nr / BITS_PER_LONG])) != 0;
    5ff2:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
		return ctrl & L2CAP_CTRL_FRAME_TYPE;
    5ff9:	44 89 f8             	mov    %r15d,%eax
		len -= L2CAP_SDULEN_SIZE;
    5ffc:	8d 73 fe             	lea    -0x2(%rbx),%esi
    5fff:	83 e0 01             	and    $0x1,%eax
    6002:	84 c0                	test   %al,%al
    6004:	0f 45 f3             	cmovne %ebx,%esi
    6007:	e9 8b fc ff ff       	jmpq   5c97 <l2cap_ertm_data_rcv+0xf7>
    600c:	0f 1f 40 00          	nopl   0x0(%rax)
		return chan->tx_win_max + 1 - seq2 + seq1;
    6010:	45 0f b7 45 72       	movzwl 0x72(%r13),%r8d
    6015:	41 29 f8             	sub    %edi,%r8d
    6018:	41 8d 44 08 01       	lea    0x1(%r8,%rcx,1),%eax
    601d:	e9 d7 fc ff ff       	jmpq   5cf9 <l2cap_ertm_data_rcv+0x159>
    6022:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    6028:	41 0f b7 4d 72       	movzwl 0x72(%r13),%ecx
    602d:	0f b7 d2             	movzwl %dx,%edx
    6030:	29 f9                	sub    %edi,%ecx
    6032:	8d 54 11 01          	lea    0x1(%rcx,%rdx,1),%edx
    6036:	e9 a8 fc ff ff       	jmpq   5ce3 <l2cap_ertm_data_rcv+0x143>
    603b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		return (ctrl & L2CAP_CTRL_REQSEQ) >> L2CAP_CTRL_REQSEQ_SHIFT;
    6040:	81 e2 00 3f 00 00    	and    $0x3f00,%edx
    6046:	c1 ea 08             	shr    $0x8,%edx
    6049:	e9 7c fc ff ff       	jmpq   5cca <l2cap_ertm_data_rcv+0x12a>
    604e:	66 90                	xchg   %ax,%ax
		control->poll = (ext & L2CAP_EXT_CTRL_POLL) >> L2CAP_EXT_CTRL_POLL_SHIFT;
    6050:	89 d6                	mov    %edx,%esi
		control->sframe = 1;
    6052:	83 c8 01             	or     $0x1,%eax
		control->super = (ext & L2CAP_EXT_CTRL_SUPERVISE) >> L2CAP_EXT_CTRL_SUPER_SHIFT;
    6055:	c1 ea 0a             	shr    $0xa,%edx
		control->poll = (ext & L2CAP_EXT_CTRL_POLL) >> L2CAP_EXT_CTRL_POLL_SHIFT;
    6058:	c1 ee 12             	shr    $0x12,%esi
    605b:	83 e0 3d             	and    $0x3d,%eax
    605e:	83 e6 01             	and    $0x1,%esi
    6061:	01 f6                	add    %esi,%esi
    6063:	e9 5b fe ff ff       	jmpq   5ec3 <l2cap_ertm_data_rcv+0x323>
    6068:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    606f:	00 
		l2cap_data_channel_sframe(chan, control, skb);
    6070:	4c 89 e2             	mov    %r12,%rdx
    6073:	44 89 fe             	mov    %r15d,%esi
    6076:	4c 89 ef             	mov    %r13,%rdi
    6079:	e8 42 ea ff ff       	callq  4ac0 <l2cap_data_channel_sframe>
    607e:	e9 bd fe ff ff       	jmpq   5f40 <l2cap_ertm_data_rcv+0x3a0>
    6083:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		return (ctrl & L2CAP_CTRL_TXSEQ) >> L2CAP_CTRL_TXSEQ_SHIFT;
    6088:	44 89 fb             	mov    %r15d,%ebx
    608b:	83 e3 7e             	and    $0x7e,%ebx
    608e:	d1 eb                	shr    %ebx
    6090:	e9 a0 fc ff ff       	jmpq   5d35 <l2cap_ertm_data_rcv+0x195>
    6095:	0f 1f 00             	nopl   (%rax)
		return (ctrl & L2CAP_CTRL_SAR) >> L2CAP_CTRL_SAR_SHIFT;
    6098:	25 00 c0 00 00       	and    $0xc000,%eax
    609d:	c1 e8 0e             	shr    $0xe,%eax
    60a0:	89 45 c8             	mov    %eax,-0x38(%rbp)
    60a3:	e9 c7 fc ff ff       	jmpq   5d6f <l2cap_ertm_data_rcv+0x1cf>
    60a8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    60af:	00 
		return (ctrl & L2CAP_CTRL_REQSEQ) >> L2CAP_CTRL_REQSEQ_SHIFT;
    60b0:	41 81 e3 00 3f 00 00 	and    $0x3f00,%r11d
    60b7:	41 c1 eb 08          	shr    $0x8,%r11d
    60bb:	e9 92 fc ff ff       	jmpq   5d52 <l2cap_ertm_data_rcv+0x1b2>
		return ctrl & L2CAP_CTRL_FINAL;
    60c0:	c1 e8 07             	shr    $0x7,%eax
    60c3:	83 e0 01             	and    $0x1,%eax
    60c6:	e9 d5 fc ff ff       	jmpq   5da0 <l2cap_ertm_data_rcv+0x200>
    60cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		return chan->tx_win_max + 1 - seq2 + seq1;
    60d0:	41 0f b7 55 72       	movzwl 0x72(%r13),%edx
    60d5:	0f b7 c8             	movzwl %ax,%ecx
    60d8:	29 ca                	sub    %ecx,%edx
    60da:	42 8d 54 32 01       	lea    0x1(%rdx,%r14,1),%edx
    60df:	e9 f8 fc ff ff       	jmpq   5ddc <l2cap_ertm_data_rcv+0x23c>
	ret = del_timer_sync(&work->timer);
    60e4:	49 8d bd f0 01 00 00 	lea    0x1f0(%r13),%rdi
    60eb:	44 89 5d b8          	mov    %r11d,-0x48(%rbp)
    60ef:	e8 00 00 00 00       	callq  60f4 <l2cap_ertm_data_rcv+0x554>
	if (ret)
    60f4:	85 c0                	test   %eax,%eax
    60f6:	44 8b 5d b8          	mov    -0x48(%rbp),%r11d
    60fa:	74 19                	je     6115 <l2cap_ertm_data_rcv+0x575>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    60fc:	f0 41 80 a5 d0 01 00 	lock andb $0xfe,0x1d0(%r13)
    6103:	00 fe 
    6105:	f0 41 ff 4d 14       	lock decl 0x14(%r13)
    610a:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    610d:	84 c0                	test   %al,%al
    610f:	0f 85 53 06 00 00    	jne    6768 <l2cap_ertm_data_rcv+0xbc8>
		if (chan->unacked_frames > 0)
    6115:	66 41 83 bd a8 00 00 	cmpw   $0x0,0xa8(%r13)
    611c:	00 00 
    611e:	0f 85 53 01 00 00    	jne    6277 <l2cap_ertm_data_rcv+0x6d7>
    6124:	f0 41 80 a5 88 00 00 	lock andb $0xfd,0x88(%r13)
    612b:	00 fd 
    612d:	e9 81 fc ff ff       	jmpq   5db3 <l2cap_ertm_data_rcv+0x213>
	if (seq1 >= seq2)
    6132:	66 39 f0             	cmp    %si,%ax
    6135:	0f 87 2b 01 00 00    	ja     6266 <l2cap_ertm_data_rcv+0x6c6>
		return seq1 - seq2;
    613b:	29 ce                	sub    %ecx,%esi
		if (tx_seq_offset < expected_tx_seq_offset)
    613d:	39 f2                	cmp    %esi,%edx
    613f:	90                   	nop
    6140:	0f 8c f2 fd ff ff    	jl     5f38 <l2cap_ertm_data_rcv+0x398>
		asm volatile(LOCK_PREFIX "orb %1,%0"
    6146:	f0 41 80 8d 88 00 00 	lock orb $0x1,0x88(%r13)
    614d:	00 01 
		BT_DBG("chan %p, Enter SREJ", chan);
    614f:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 6156 <l2cap_ertm_data_rcv+0x5b6>
    6156:	0f 85 2b 07 00 00    	jne    6887 <l2cap_ertm_data_rcv+0xce7>
		INIT_LIST_HEAD(&chan->srej_l);
    615c:	49 8d 85 08 03 00 00 	lea    0x308(%r13),%rax
		l2cap_add_to_srej_queue(chan, skb, tx_seq, sar);
    6163:	0f b6 4d c8          	movzbl -0x38(%rbp),%ecx
    6167:	44 89 f2             	mov    %r14d,%edx
    616a:	4c 89 e6             	mov    %r12,%rsi
    616d:	4c 89 ef             	mov    %r13,%rdi
	list->qlen = 0;
    6170:	41 c7 85 e0 02 00 00 	movl   $0x0,0x2e0(%r13)
    6177:	00 00 00 00 
	list->next = list;
    617b:	49 89 85 08 03 00 00 	mov    %rax,0x308(%r13)
	list->prev = list;
    6182:	49 89 85 10 03 00 00 	mov    %rax,0x310(%r13)
		chan->buffer_seq_srej = chan->buffer_seq;
    6189:	41 0f b7 85 9e 00 00 	movzwl 0x9e(%r13),%eax
    6190:	00 
    6191:	66 41 89 85 a0 00 00 	mov    %ax,0xa0(%r13)
    6198:	00 
		__skb_queue_head_init(&chan->srej_q);
    6199:	49 8d 85 d0 02 00 00 	lea    0x2d0(%r13),%rax
	list->prev = list->next = (struct sk_buff *)list;
    61a0:	49 89 85 d0 02 00 00 	mov    %rax,0x2d0(%r13)
    61a7:	49 89 85 d8 02 00 00 	mov    %rax,0x2d8(%r13)
		l2cap_add_to_srej_queue(chan, skb, tx_seq, sar);
    61ae:	e8 0d e8 ff ff       	callq  49c0 <l2cap_add_to_srej_queue>
	ret = del_timer_sync(&work->timer);
    61b3:	49 8d bd 60 02 00 00 	lea    0x260(%r13),%rdi
    61ba:	e8 00 00 00 00       	callq  61bf <l2cap_ertm_data_rcv+0x61f>
	if (ret)
    61bf:	85 c0                	test   %eax,%eax
    61c1:	0f 84 c0 fc ff ff    	je     5e87 <l2cap_ertm_data_rcv+0x2e7>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    61c7:	f0 41 80 a5 40 02 00 	lock andb $0xfe,0x240(%r13)
    61ce:	00 fe 
    61d0:	f0 41 ff 4d 14       	lock decl 0x14(%r13)
    61d5:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    61d8:	84 c0                	test   %al,%al
    61da:	0f 85 3f 06 00 00    	jne    681f <l2cap_ertm_data_rcv+0xc7f>
		asm volatile(LOCK_PREFIX "orb %1,%0"
    61e0:	f0 41 80 8d 88 00 00 	lock orb $0x8,0x88(%r13)
    61e7:	00 08 
    61e9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    61f0:	e9 92 fc ff ff       	jmpq   5e87 <l2cap_ertm_data_rcv+0x2e7>
	return (seq + 1) % (chan->tx_win_max + 1);
    61f5:	41 0f b7 4d 72       	movzwl 0x72(%r13),%ecx
    61fa:	41 8d 46 01          	lea    0x1(%r14),%eax
    61fe:	99                   	cltd   
    61ff:	83 c1 01             	add    $0x1,%ecx
    6202:	f7 f9                	idiv   %ecx
		(addr[nr / BITS_PER_LONG])) != 0;
    6204:	49 8b 85 88 00 00 00 	mov    0x88(%r13),%rax
	if (test_bit(CONN_SREJ_SENT, &chan->conn_state)) {
    620b:	a8 01                	test   $0x1,%al
    620d:	66 41 89 95 9c 00 00 	mov    %dx,0x9c(%r13)
    6214:	00 
    6215:	0f 84 c9 00 00 00    	je     62e4 <l2cap_ertm_data_rcv+0x744>
		bt_cb(skb)->control.sar = sar;
    621b:	41 0f b6 44 24 30    	movzbl 0x30(%r12),%eax
    6221:	0f b6 55 c8          	movzbl -0x38(%rbp),%edx
		bt_cb(skb)->control.txseq = tx_seq;
    6225:	66 41 89 5c 24 34    	mov    %bx,0x34(%r12)
		bt_cb(skb)->control.sar = sar;
    622b:	c1 e2 04             	shl    $0x4,%edx
    622e:	83 e0 cf             	and    $0xffffffcf,%eax
    6231:	09 d0                	or     %edx,%eax
		__skb_queue_tail(&chan->srej_q, skb);
    6233:	49 8d 95 d0 02 00 00 	lea    0x2d0(%r13),%rdx
		bt_cb(skb)->control.sar = sar;
    623a:	41 88 44 24 30       	mov    %al,0x30(%r12)
	__skb_insert(newsk, next->prev, next, list);
    623f:	49 8b 85 d8 02 00 00 	mov    0x2d8(%r13),%rax
		__skb_queue_tail(&chan->srej_q, skb);
    6246:	49 89 14 24          	mov    %rdx,(%r12)
	newsk->prev = prev;
    624a:	49 89 44 24 08       	mov    %rax,0x8(%r12)
	next->prev  = prev->next = newsk;
    624f:	4c 89 20             	mov    %r12,(%rax)
    6252:	4d 89 a5 d8 02 00 00 	mov    %r12,0x2d8(%r13)
	list->qlen++;
    6259:	41 83 85 e0 02 00 00 	addl   $0x1,0x2e0(%r13)
    6260:	01 
    6261:	e9 da fc ff ff       	jmpq   5f40 <l2cap_ertm_data_rcv+0x3a0>
		return chan->tx_win_max + 1 - seq2 + seq1;
    6266:	41 0f b7 45 72       	movzwl 0x72(%r13),%eax
    626b:	83 c0 01             	add    $0x1,%eax
    626e:	29 c8                	sub    %ecx,%eax
    6270:	01 c6                	add    %eax,%esi
    6272:	e9 c6 fe ff ff       	jmpq   613d <l2cap_ertm_data_rcv+0x59d>
			__set_retrans_timer(chan);
    6277:	bf d0 07 00 00       	mov    $0x7d0,%edi
    627c:	44 89 5d c0          	mov    %r11d,-0x40(%rbp)
    6280:	e8 00 00 00 00       	callq  6285 <l2cap_ertm_data_rcv+0x6e5>
	BT_DBG("chan %p state %s timeout %ld", chan,
    6285:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 628c <l2cap_ertm_data_rcv+0x6ec>
    628c:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    6290:	49 8d 85 60 01 00 00 	lea    0x160(%r13),%rax
    6297:	44 8b 5d c0          	mov    -0x40(%rbp),%r11d
    629b:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
    629f:	0f 85 9d 05 00 00    	jne    6842 <l2cap_ertm_data_rcv+0xca2>
	ret = del_timer_sync(&work->timer);
    62a5:	49 8d bd 80 01 00 00 	lea    0x180(%r13),%rdi
    62ac:	44 89 5d c0          	mov    %r11d,-0x40(%rbp)
    62b0:	e8 00 00 00 00       	callq  62b5 <l2cap_ertm_data_rcv+0x715>
	if (ret)
    62b5:	85 c0                	test   %eax,%eax
    62b7:	44 8b 5d c0          	mov    -0x40(%rbp),%r11d
    62bb:	0f 84 c9 04 00 00    	je     678a <l2cap_ertm_data_rcv+0xbea>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    62c1:	f0 41 80 a5 60 01 00 	lock andb $0xfe,0x160(%r13)
    62c8:	00 fe 
	schedule_delayed_work(work, timeout);
    62ca:	48 8b 75 b8          	mov    -0x48(%rbp),%rsi
    62ce:	48 8b 7d b0          	mov    -0x50(%rbp),%rdi
    62d2:	44 89 5d c0          	mov    %r11d,-0x40(%rbp)
    62d6:	e8 00 00 00 00       	callq  62db <l2cap_ertm_data_rcv+0x73b>
    62db:	44 8b 5d c0          	mov    -0x40(%rbp),%r11d
    62df:	e9 40 fe ff ff       	jmpq   6124 <l2cap_ertm_data_rcv+0x584>
	err = l2cap_reassemble_sdu(chan, skb, rx_control);
    62e4:	44 89 fa             	mov    %r15d,%edx
    62e7:	4c 89 e6             	mov    %r12,%rsi
    62ea:	4c 89 ef             	mov    %r13,%rdi
    62ed:	e8 2e ae ff ff       	callq  1120 <l2cap_reassemble_sdu>
	return (seq + 1) % (chan->tx_win_max + 1);
    62f2:	41 0f b7 95 9e 00 00 	movzwl 0x9e(%r13),%edx
    62f9:	00 
    62fa:	41 0f b7 4d 72       	movzwl 0x72(%r13),%ecx
    62ff:	89 c6                	mov    %eax,%esi
    6301:	8d 42 01             	lea    0x1(%rdx),%eax
    6304:	83 c1 01             	add    $0x1,%ecx
    6307:	99                   	cltd   
    6308:	f7 f9                	idiv   %ecx
	if (err < 0) {
    630a:	85 f6                	test   %esi,%esi
    630c:	66 41 89 95 9e 00 00 	mov    %dx,0x9e(%r13)
    6313:	00 
    6314:	0f 88 12 05 00 00    	js     682c <l2cap_ertm_data_rcv+0xc8c>
		(addr[nr / BITS_PER_LONG])) != 0;
    631a:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    6321:	a8 10                	test   $0x10,%al
    6323:	0f 84 54 04 00 00    	je     677d <l2cap_ertm_data_rcv+0xbdd>
		return ctrl & L2CAP_EXT_CTRL_FINAL;
    6329:	41 d1 ef             	shr    %r15d
    632c:	41 83 e7 01          	and    $0x1,%r15d
	if (__is_ctrl_final(chan, rx_control)) {
    6330:	45 84 ff             	test   %r15b,%r15b
    6333:	74 42                	je     6377 <l2cap_ertm_data_rcv+0x7d7>
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    6335:	f0 41 0f ba b5 88 00 	lock btrl $0x6,0x88(%r13)
    633c:	00 00 06 
    633f:	19 c0                	sbb    %eax,%eax
		if (!test_and_clear_bit(CONN_REJ_ACT, &chan->conn_state))
    6341:	85 c0                	test   %eax,%eax
    6343:	75 32                	jne    6377 <l2cap_ertm_data_rcv+0x7d7>
	return list->next == (struct sk_buff *)list;
    6345:	49 8b 85 b8 02 00 00 	mov    0x2b8(%r13),%rax
	if (!skb_queue_empty(&chan->tx_q))
    634c:	49 8d 95 b8 02 00 00 	lea    0x2b8(%r13),%rdx
    6353:	48 39 d0             	cmp    %rdx,%rax
    6356:	74 07                	je     635f <l2cap_ertm_data_rcv+0x7bf>
		chan->tx_send_head = chan->tx_q.next;
    6358:	49 89 85 b0 02 00 00 	mov    %rax,0x2b0(%r13)
	chan->next_tx_seq = chan->expected_ack_seq;
    635f:	41 0f b7 85 9a 00 00 	movzwl 0x9a(%r13),%eax
    6366:	00 
	ret = l2cap_ertm_send(chan);
    6367:	4c 89 ef             	mov    %r13,%rdi
	chan->next_tx_seq = chan->expected_ack_seq;
    636a:	66 41 89 85 98 00 00 	mov    %ax,0x98(%r13)
    6371:	00 
	ret = l2cap_ertm_send(chan);
    6372:	e8 d9 c6 ff ff       	callq  2a50 <l2cap_ertm_send>
	int num_to_ack = (chan->tx_win/6) + 1;
    6377:	0f b7 4d c6          	movzwl -0x3a(%rbp),%ecx
	chan->num_acked = (chan->num_acked + 1) % num_to_ack;
    637b:	41 0f b6 85 ae 00 00 	movzbl 0xae(%r13),%eax
    6382:	00 
	int num_to_ack = (chan->tx_win/6) + 1;
    6383:	69 c9 ab aa 00 00    	imul   $0xaaab,%ecx,%ecx
	chan->num_acked = (chan->num_acked + 1) % num_to_ack;
    6389:	83 c0 01             	add    $0x1,%eax
    638c:	99                   	cltd   
	int num_to_ack = (chan->tx_win/6) + 1;
    638d:	c1 e9 12             	shr    $0x12,%ecx
    6390:	8d 71 01             	lea    0x1(%rcx),%esi
	chan->num_acked = (chan->num_acked + 1) % num_to_ack;
    6393:	f7 fe                	idiv   %esi
    6395:	41 88 95 ae 00 00 00 	mov    %dl,0xae(%r13)
	if (chan->num_acked == num_to_ack - 1)
    639c:	0f b6 d2             	movzbl %dl,%edx
    639f:	39 d1                	cmp    %edx,%ecx
    63a1:	0f 84 46 04 00 00    	je     67ed <l2cap_ertm_data_rcv+0xc4d>
		__set_ack_timer(chan);
    63a7:	bf c8 00 00 00       	mov    $0xc8,%edi
    63ac:	4d 8d a5 40 02 00 00 	lea    0x240(%r13),%r12
    63b3:	e8 00 00 00 00       	callq  63b8 <l2cap_ertm_data_rcv+0x818>
	BT_DBG("chan %p state %s timeout %ld", chan,
    63b8:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 63bf <l2cap_ertm_data_rcv+0x81f>
    63bf:	48 89 c3             	mov    %rax,%rbx
    63c2:	0f 85 dc 04 00 00    	jne    68a4 <l2cap_ertm_data_rcv+0xd04>
	ret = del_timer_sync(&work->timer);
    63c8:	49 8d bd 60 02 00 00 	lea    0x260(%r13),%rdi
    63cf:	e8 00 00 00 00       	callq  63d4 <l2cap_ertm_data_rcv+0x834>
	if (ret)
    63d4:	85 c0                	test   %eax,%eax
    63d6:	0f 84 07 04 00 00    	je     67e3 <l2cap_ertm_data_rcv+0xc43>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    63dc:	f0 41 80 a5 40 02 00 	lock andb $0xfe,0x240(%r13)
    63e3:	00 fe 
	schedule_delayed_work(work, timeout);
    63e5:	48 89 de             	mov    %rbx,%rsi
    63e8:	4c 89 e7             	mov    %r12,%rdi
    63eb:	e8 00 00 00 00       	callq  63f0 <l2cap_ertm_data_rcv+0x850>
    63f0:	e9 4b fb ff ff       	jmpq   5f40 <l2cap_ertm_data_rcv+0x3a0>
			l2cap_add_to_srej_queue(chan, skb, tx_seq, sar);
    63f5:	e8 c6 e5 ff ff       	callq  49c0 <l2cap_add_to_srej_queue>
	struct sk_buff *skb = list_->next;
    63fa:	49 8b 85 d0 02 00 00 	mov    0x2d0(%r13),%rax
	while ((skb = skb_peek(&chan->srej_q)) &&
    6401:	4d 8d a5 d0 02 00 00 	lea    0x2d0(%r13),%r12
	if (skb == (struct sk_buff *)list_)
    6408:	49 39 c4             	cmp    %rax,%r12
    640b:	0f 84 b8 00 00 00    	je     64c9 <l2cap_ertm_data_rcv+0x929>
    6411:	48 85 c0             	test   %rax,%rax
    6414:	0f 84 af 00 00 00    	je     64c9 <l2cap_ertm_data_rcv+0x929>
		(addr[nr / BITS_PER_LONG])) != 0;
    641a:	49 8b 95 88 00 00 00 	mov    0x88(%r13),%rdx
    6421:	83 e2 20             	and    $0x20,%edx
    6424:	0f 85 9f 00 00 00    	jne    64c9 <l2cap_ertm_data_rcv+0x929>
		if (bt_cb(skb)->control.txseq != tx_seq)
    642a:	66 3b 58 34          	cmp    0x34(%rax),%bx
    642e:	74 25                	je     6455 <l2cap_ertm_data_rcv+0x8b5>
    6430:	e9 94 00 00 00       	jmpq   64c9 <l2cap_ertm_data_rcv+0x929>
    6435:	0f 1f 00             	nopl   (%rax)
	while ((skb = skb_peek(&chan->srej_q)) &&
    6438:	48 85 c9             	test   %rcx,%rcx
    643b:	0f 84 88 00 00 00    	je     64c9 <l2cap_ertm_data_rcv+0x929>
    6441:	49 8b 85 88 00 00 00 	mov    0x88(%r13),%rax
    6448:	a8 20                	test   $0x20,%al
    644a:	75 7d                	jne    64c9 <l2cap_ertm_data_rcv+0x929>
		if (bt_cb(skb)->control.txseq != tx_seq)
    644c:	0f b7 59 34          	movzwl 0x34(%rcx),%ebx
    6450:	66 39 d3             	cmp    %dx,%bx
    6453:	75 74                	jne    64c9 <l2cap_ertm_data_rcv+0x929>
		skb = skb_dequeue(&chan->srej_q);
    6455:	4c 89 e7             	mov    %r12,%rdi
    6458:	e8 00 00 00 00       	callq  645d <l2cap_ertm_data_rcv+0x8bd>
		control = __set_ctrl_sar(chan, bt_cb(skb)->control.sar);
    645d:	0f b6 50 30          	movzbl 0x30(%rax),%edx
    6461:	49 8b b5 90 00 00 00 	mov    0x90(%r13),%rsi
    6468:	c0 ea 04             	shr    $0x4,%dl
    646b:	89 d1                	mov    %edx,%ecx
    646d:	83 e1 03             	and    $0x3,%ecx
		return (sar << L2CAP_CTRL_SAR_SHIFT) & L2CAP_CTRL_SAR;
    6470:	89 ca                	mov    %ecx,%edx
    6472:	c1 e2 0e             	shl    $0xe,%edx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    6475:	83 e6 10             	and    $0x10,%esi
    6478:	74 05                	je     647f <l2cap_ertm_data_rcv+0x8df>
		return (sar << L2CAP_EXT_CTRL_SAR_SHIFT) & L2CAP_EXT_CTRL_SAR;
    647a:	c1 e1 10             	shl    $0x10,%ecx
    647d:	89 ca                	mov    %ecx,%edx
		err = l2cap_reassemble_sdu(chan, skb, control);
    647f:	48 89 c6             	mov    %rax,%rsi
    6482:	4c 89 ef             	mov    %r13,%rdi
    6485:	e8 96 ac ff ff       	callq  1120 <l2cap_reassemble_sdu>
		if (err < 0) {
    648a:	85 c0                	test   %eax,%eax
    648c:	0f 88 77 03 00 00    	js     6809 <l2cap_ertm_data_rcv+0xc69>
	return (seq + 1) % (chan->tx_win_max + 1);
    6492:	41 0f b7 85 a0 00 00 	movzwl 0xa0(%r13),%eax
    6499:	00 
    649a:	41 0f b7 4d 72       	movzwl 0x72(%r13),%ecx
    649f:	83 c0 01             	add    $0x1,%eax
    64a2:	83 c1 01             	add    $0x1,%ecx
    64a5:	99                   	cltd   
    64a6:	f7 f9                	idiv   %ecx
    64a8:	0f b7 c3             	movzwl %bx,%eax
    64ab:	83 c0 01             	add    $0x1,%eax
    64ae:	66 41 89 95 a0 00 00 	mov    %dx,0xa0(%r13)
    64b5:	00 
    64b6:	99                   	cltd   
    64b7:	f7 f9                	idiv   %ecx
	struct sk_buff *skb = list_->next;
    64b9:	49 8b 8d d0 02 00 00 	mov    0x2d0(%r13),%rcx
	if (skb == (struct sk_buff *)list_)
    64c0:	49 39 cc             	cmp    %rcx,%r12
    64c3:	0f 85 6f ff ff ff    	jne    6438 <l2cap_ertm_data_rcv+0x898>
			list_del(&first->list);
    64c9:	49 8d 5f f8          	lea    -0x8(%r15),%rbx
    64cd:	4c 89 ff             	mov    %r15,%rdi
    64d0:	e8 00 00 00 00       	callq  64d5 <l2cap_ertm_data_rcv+0x935>
			kfree(first);
    64d5:	48 89 df             	mov    %rbx,%rdi
    64d8:	e8 00 00 00 00       	callq  64dd <l2cap_ertm_data_rcv+0x93d>
			if (list_empty(&chan->srej_l)) {
    64dd:	49 8d 85 08 03 00 00 	lea    0x308(%r13),%rax
    64e4:	49 39 85 08 03 00 00 	cmp    %rax,0x308(%r13)
    64eb:	0f 85 4f fa ff ff    	jne    5f40 <l2cap_ertm_data_rcv+0x3a0>
				chan->buffer_seq = chan->buffer_seq_srej;
    64f1:	41 0f b7 85 a0 00 00 	movzwl 0xa0(%r13),%eax
    64f8:	00 
    64f9:	66 41 89 85 9e 00 00 	mov    %ax,0x9e(%r13)
    6500:	00 
		asm volatile(LOCK_PREFIX "andb %1,%0"
    6501:	f0 41 80 a5 88 00 00 	lock andb $0xfe,0x88(%r13)
    6508:	00 fe 
	__clear_ack_timer(chan);
    650a:	49 8d b5 40 02 00 00 	lea    0x240(%r13),%rsi
    6511:	4c 89 ef             	mov    %r13,%rdi
    6514:	e8 e7 be ff ff       	callq  2400 <l2cap_clear_timer>
	__l2cap_send_ack(chan);
    6519:	4c 89 ef             	mov    %r13,%rdi
    651c:	e8 cf d6 ff ff       	callq  3bf0 <__l2cap_send_ack>
				BT_DBG("chan %p, Exit SREJ_SENT", chan);
    6521:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 6528 <l2cap_ertm_data_rcv+0x988>
    6528:	0f 84 12 fa ff ff    	je     5f40 <l2cap_ertm_data_rcv+0x3a0>
    652e:	4c 89 ea             	mov    %r13,%rdx
    6531:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    6538:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    653f:	31 c0                	xor    %eax,%eax
    6541:	e8 00 00 00 00       	callq  6546 <l2cap_ertm_data_rcv+0x9a6>
    6546:	e9 f5 f9 ff ff       	jmpq   5f40 <l2cap_ertm_data_rcv+0x3a0>
    654b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
	list_for_each_entry_safe(l, tmp, &chan->srej_l, list) {
    6550:	4c 8b 01             	mov    (%rcx),%r8
    6553:	4c 89 65 c8          	mov    %r12,-0x38(%rbp)
    6557:	49 89 fe             	mov    %rdi,%r14
    655a:	4d 89 ec             	mov    %r13,%r12
    655d:	66 89 5d c6          	mov    %bx,-0x3a(%rbp)
    6561:	4d 8d 78 f8          	lea    -0x8(%r8),%r15
    6565:	4d 89 fd             	mov    %r15,%r13
    6568:	eb 5d                	jmp    65c7 <l2cap_ertm_data_rcv+0xa27>
		return (reqseq << L2CAP_EXT_CTRL_REQSEQ_SHIFT) &
    656a:	c1 e2 02             	shl    $0x2,%edx
    656d:	0f b7 da             	movzwl %dx,%ebx
	if (chan->state != BT_CONNECTED)
    6570:	41 80 7c 24 10 01    	cmpb   $0x1,0x10(%r12)
	struct l2cap_conn *conn = chan->conn;
    6576:	4d 8b 7c 24 08       	mov    0x8(%r12),%r15
	if (chan->state != BT_CONNECTED)
    657b:	0f 84 82 00 00 00    	je     6603 <l2cap_ertm_data_rcv+0xa63>
		list_del(&l->list);
    6581:	4c 89 f7             	mov    %r14,%rdi
    6584:	e8 00 00 00 00       	callq  6589 <l2cap_ertm_data_rcv+0x9e9>
	__list_add(new, head->prev, head);
    6589:	48 8b 5d c8          	mov    -0x38(%rbp),%rbx
    658d:	49 8b b4 24 10 03 00 	mov    0x310(%r12),%rsi
    6594:	00 
    6595:	4c 89 f7             	mov    %r14,%rdi
	list_for_each_entry_safe(l, tmp, &chan->srej_l, list) {
    6598:	4d 8d 75 08          	lea    0x8(%r13),%r14
    659c:	48 89 da             	mov    %rbx,%rdx
    659f:	e8 00 00 00 00       	callq  65a4 <l2cap_ertm_data_rcv+0xa04>
    65a4:	49 8b 45 08          	mov    0x8(%r13),%rax
    65a8:	48 83 e8 08          	sub    $0x8,%rax
    65ac:	4c 39 f3             	cmp    %r14,%rbx
    65af:	0f 84 8b f9 ff ff    	je     5f40 <l2cap_ertm_data_rcv+0x3a0>
		if (l->tx_seq == tx_seq) {
    65b5:	41 0f b7 55 00       	movzwl 0x0(%r13),%edx
    65ba:	66 39 55 c6          	cmp    %dx,-0x3a(%rbp)
    65be:	0f 84 d0 01 00 00    	je     6794 <l2cap_ertm_data_rcv+0xbf4>
	list_for_each_entry_safe(l, tmp, &chan->srej_l, list) {
    65c4:	49 89 c5             	mov    %rax,%r13
		(addr[nr / BITS_PER_LONG])) != 0;
    65c7:	49 8b 84 24 90 00 00 	mov    0x90(%r12),%rax
    65ce:	00 
    65cf:	49 8b 8c 24 90 00 00 	mov    0x90(%r12),%rcx
    65d6:	00 
    65d7:	83 e0 10             	and    $0x10,%eax
		return (super << L2CAP_EXT_CTRL_SUPER_SHIFT) &
    65da:	48 83 f8 01          	cmp    $0x1,%rax
    65de:	19 c0                	sbb    %eax,%eax
    65e0:	25 0c 00 fd ff       	and    $0xfffd000c,%eax
    65e5:	05 00 00 03 00       	add    $0x30000,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    65ea:	83 e1 10             	and    $0x10,%ecx
    65ed:	0f 85 77 ff ff ff    	jne    656a <l2cap_ertm_data_rcv+0x9ca>
		return (reqseq << L2CAP_CTRL_REQSEQ_SHIFT) & L2CAP_CTRL_REQSEQ;
    65f3:	89 d3                	mov    %edx,%ebx
    65f5:	c1 e3 08             	shl    $0x8,%ebx
    65f8:	81 e3 00 3f 00 00    	and    $0x3f00,%ebx
    65fe:	e9 6d ff ff ff       	jmpq   6570 <l2cap_ertm_data_rcv+0x9d0>
    6603:	49 8b 94 24 90 00 00 	mov    0x90(%r12),%rdx
    660a:	00 
    660b:	83 e2 10             	and    $0x10,%edx
		hlen = L2CAP_EXT_HDR_SIZE;
    660e:	48 83 fa 01          	cmp    $0x1,%rdx
    6612:	45 19 c9             	sbb    %r9d,%r9d
    6615:	41 83 e1 fe          	and    $0xfffffffe,%r9d
    6619:	41 83 c1 08          	add    $0x8,%r9d
		hlen += L2CAP_FCS_SIZE;
    661d:	41 80 7c 24 6f 01    	cmpb   $0x1,0x6f(%r12)
    6623:	41 8d 51 02          	lea    0x2(%r9),%edx
    6627:	44 0f 44 ca          	cmove  %edx,%r9d
		control |= __set_reqseq(chan, l->tx_seq);
    662b:	09 c3                	or     %eax,%ebx
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    662d:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 6634 <l2cap_ertm_data_rcv+0xa94>
    6634:	0f 85 da 02 00 00    	jne    6914 <l2cap_ertm_data_rcv+0xd74>
	count = min_t(unsigned int, conn->mtu, hlen);
    663a:	45 8b 7f 20          	mov    0x20(%r15),%r15d
    663e:	49 8b 84 24 90 00 00 	mov    0x90(%r12),%rax
    6645:	00 
    6646:	45 39 f9             	cmp    %r15d,%r9d
    6649:	45 0f 46 f9          	cmovbe %r9d,%r15d
	control |= __set_sframe(chan);
    664d:	83 cb 01             	or     $0x1,%ebx
	count = min_t(unsigned int, conn->mtu, hlen);
    6650:	44 89 7d b8          	mov    %r15d,-0x48(%rbp)
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    6654:	f0 41 0f ba b4 24 88 	lock btrl $0x7,0x88(%r12)
    665b:	00 00 00 07 
    665f:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_FBIT, &chan->conn_state))
    6661:	85 c0                	test   %eax,%eax
    6663:	74 19                	je     667e <l2cap_ertm_data_rcv+0xade>
		(addr[nr / BITS_PER_LONG])) != 0;
    6665:	49 8b 84 24 90 00 00 	mov    0x90(%r12),%rax
    666c:	00 
    666d:	83 e0 10             	and    $0x10,%eax
		return L2CAP_EXT_CTRL_FINAL;
    6670:	48 83 f8 01          	cmp    $0x1,%rax
    6674:	19 c0                	sbb    %eax,%eax
    6676:	83 e0 7e             	and    $0x7e,%eax
    6679:	83 c0 02             	add    $0x2,%eax
		control |= __set_ctrl_final(chan);
    667c:	09 c3                	or     %eax,%ebx
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    667e:	f0 41 0f ba b4 24 88 	lock btrl $0x3,0x88(%r12)
    6685:	00 00 00 03 
    6689:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_PBIT, &chan->conn_state))
    668b:	85 c0                	test   %eax,%eax
    668d:	74 1d                	je     66ac <l2cap_ertm_data_rcv+0xb0c>
		(addr[nr / BITS_PER_LONG])) != 0;
    668f:	49 8b 84 24 90 00 00 	mov    0x90(%r12),%rax
    6696:	00 
    6697:	83 e0 10             	and    $0x10,%eax
		return L2CAP_EXT_CTRL_POLL;
    669a:	48 83 f8 01          	cmp    $0x1,%rax
    669e:	19 c0                	sbb    %eax,%eax
    66a0:	25 10 00 fc ff       	and    $0xfffc0010,%eax
    66a5:	05 00 00 04 00       	add    $0x40000,%eax
		control |= __set_ctrl_poll(chan);
    66aa:	09 c3                	or     %eax,%ebx
	if ((skb = alloc_skb(len + BT_SKB_RESERVE, how))) {
    66ac:	8b 45 b8             	mov    -0x48(%rbp),%eax
	return __alloc_skb(size, priority, 0, NUMA_NO_NODE);
    66af:	31 d2                	xor    %edx,%edx
    66b1:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    66b6:	be 20 00 00 00       	mov    $0x20,%esi
    66bb:	44 89 4d b0          	mov    %r9d,-0x50(%rbp)
    66bf:	8d 78 08             	lea    0x8(%rax),%edi
    66c2:	e8 00 00 00 00       	callq  66c7 <l2cap_ertm_data_rcv+0xb27>
    66c7:	48 85 c0             	test   %rax,%rax
    66ca:	49 89 c7             	mov    %rax,%r15
    66cd:	0f 84 ae fe ff ff    	je     6581 <l2cap_ertm_data_rcv+0x9e1>
	skb->data += len;
    66d3:	48 83 80 e0 00 00 00 	addq   $0x8,0xe0(%rax)
    66da:	08 
	skb->tail += len;
    66db:	83 80 cc 00 00 00 08 	addl   $0x8,0xcc(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    66e2:	be 04 00 00 00       	mov    $0x4,%esi
    66e7:	48 89 c7             	mov    %rax,%rdi
		bt_cb(skb)->incoming  = 0;
    66ea:	c6 40 29 00          	movb   $0x0,0x29(%rax)
    66ee:	e8 00 00 00 00       	callq  66f3 <l2cap_ertm_data_rcv+0xb53>
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    66f3:	44 8b 4d b0          	mov    -0x50(%rbp),%r9d
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    66f7:	49 89 c3             	mov    %rax,%r11
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    66fa:	4c 89 ff             	mov    %r15,%rdi
	lh->cid = cpu_to_le16(chan->dcid);
    66fd:	4c 89 5d b0          	mov    %r11,-0x50(%rbp)
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    6701:	41 83 e9 04          	sub    $0x4,%r9d
    6705:	66 44 89 08          	mov    %r9w,(%rax)
	lh->cid = cpu_to_le16(chan->dcid);
    6709:	41 0f b7 44 24 1a    	movzwl 0x1a(%r12),%eax
    670f:	66 41 89 43 02       	mov    %ax,0x2(%r11)
    6714:	49 8b 84 24 90 00 00 	mov    0x90(%r12),%rax
    671b:	00 
    671c:	83 e0 10             	and    $0x10,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    671f:	48 83 f8 01          	cmp    $0x1,%rax
    6723:	19 f6                	sbb    %esi,%esi
    6725:	83 e6 fe             	and    $0xfffffffe,%esi
    6728:	83 c6 04             	add    $0x4,%esi
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    672b:	e8 00 00 00 00       	callq  6730 <l2cap_ertm_data_rcv+0xb90>
    6730:	49 8b 94 24 90 00 00 	mov    0x90(%r12),%rdx
    6737:	00 
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    6738:	4c 8b 5d b0          	mov    -0x50(%rbp),%r11
    673c:	83 e2 10             	and    $0x10,%edx
    673f:	74 22                	je     6763 <l2cap_ertm_data_rcv+0xbc3>
	*((__le32 *)p) = cpu_to_le32(val);
    6741:	89 18                	mov    %ebx,(%rax)
	if (chan->fcs == L2CAP_FCS_CRC16) {
    6743:	41 80 7c 24 6f 01    	cmpb   $0x1,0x6f(%r12)
    6749:	74 6e                	je     67b9 <l2cap_ertm_data_rcv+0xc19>
	skb->priority = HCI_PRIO_MAX;
    674b:	41 c7 47 78 07 00 00 	movl   $0x7,0x78(%r15)
    6752:	00 
	l2cap_do_send(chan, skb);
    6753:	4c 89 fe             	mov    %r15,%rsi
    6756:	4c 89 e7             	mov    %r12,%rdi
    6759:	e8 a2 9d ff ff       	callq  500 <l2cap_do_send>
    675e:	e9 1e fe ff ff       	jmpq   6581 <l2cap_ertm_data_rcv+0x9e1>
    6763:	66 89 18             	mov    %bx,(%rax)
    6766:	eb db                	jmp    6743 <l2cap_ertm_data_rcv+0xba3>
		kfree(c);
    6768:	4c 89 ef             	mov    %r13,%rdi
    676b:	44 89 5d b8          	mov    %r11d,-0x48(%rbp)
    676f:	e8 00 00 00 00       	callq  6774 <l2cap_ertm_data_rcv+0xbd4>
    6774:	44 8b 5d b8          	mov    -0x48(%rbp),%r11d
    6778:	e9 98 f9 ff ff       	jmpq   6115 <l2cap_ertm_data_rcv+0x575>
		return ctrl & L2CAP_CTRL_FINAL;
    677d:	41 c1 ef 07          	shr    $0x7,%r15d
    6781:	41 83 e7 01          	and    $0x1,%r15d
    6785:	e9 a6 fb ff ff       	jmpq   6330 <l2cap_ertm_data_rcv+0x790>
	asm volatile(LOCK_PREFIX "incl %0"
    678a:	f0 41 ff 45 14       	lock incl 0x14(%r13)
    678f:	e9 36 fb ff ff       	jmpq   62ca <l2cap_ertm_data_rcv+0x72a>
    6794:	4c 89 f7             	mov    %r14,%rdi
    6797:	4d 89 ef             	mov    %r13,%r15
			list_del(&l->list);
    679a:	e8 00 00 00 00       	callq  679f <l2cap_ertm_data_rcv+0xbff>
			kfree(l);
    679f:	4c 89 ff             	mov    %r15,%rdi
    67a2:	e8 00 00 00 00       	callq  67a7 <l2cap_ertm_data_rcv+0xc07>
    67a7:	e9 94 f7 ff ff       	jmpq   5f40 <l2cap_ertm_data_rcv+0x3a0>
		kfree(c);
    67ac:	4c 89 ef             	mov    %r13,%rdi
    67af:	e8 00 00 00 00       	callq  67b4 <l2cap_ertm_data_rcv+0xc14>
    67b4:	e9 74 f7 ff ff       	jmpq   5f2d <l2cap_ertm_data_rcv+0x38d>
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    67b9:	8b 55 b8             	mov    -0x48(%rbp),%edx
    67bc:	4c 89 de             	mov    %r11,%rsi
    67bf:	31 ff                	xor    %edi,%edi
    67c1:	83 ea 02             	sub    $0x2,%edx
    67c4:	48 63 d2             	movslq %edx,%rdx
    67c7:	e8 00 00 00 00       	callq  67cc <l2cap_ertm_data_rcv+0xc2c>
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    67cc:	be 02 00 00 00       	mov    $0x2,%esi
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    67d1:	89 c3                	mov    %eax,%ebx
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    67d3:	4c 89 ff             	mov    %r15,%rdi
    67d6:	e8 00 00 00 00       	callq  67db <l2cap_ertm_data_rcv+0xc3b>
	*((__le16 *)p) = cpu_to_le16(val);
    67db:	66 89 18             	mov    %bx,(%rax)
    67de:	e9 68 ff ff ff       	jmpq   674b <l2cap_ertm_data_rcv+0xbab>
    67e3:	f0 41 ff 45 14       	lock incl 0x14(%r13)
    67e8:	e9 f8 fb ff ff       	jmpq   63e5 <l2cap_ertm_data_rcv+0x845>
	__clear_ack_timer(chan);
    67ed:	49 8d b5 40 02 00 00 	lea    0x240(%r13),%rsi
    67f4:	4c 89 ef             	mov    %r13,%rdi
    67f7:	e8 04 bc ff ff       	callq  2400 <l2cap_clear_timer>
	__l2cap_send_ack(chan);
    67fc:	4c 89 ef             	mov    %r13,%rdi
    67ff:	e8 ec d3 ff ff       	callq  3bf0 <__l2cap_send_ack>
    6804:	e9 37 f7 ff ff       	jmpq   5f40 <l2cap_ertm_data_rcv+0x3a0>
			l2cap_send_disconn_req(chan->conn, chan, ECONNRESET);
    6809:	49 8b 7d 08          	mov    0x8(%r13),%rdi
    680d:	ba 68 00 00 00       	mov    $0x68,%edx
    6812:	4c 89 ee             	mov    %r13,%rsi
    6815:	e8 e6 bd ff ff       	callq  2600 <l2cap_send_disconn_req>
    681a:	e9 aa fc ff ff       	jmpq   64c9 <l2cap_ertm_data_rcv+0x929>
    681f:	4c 89 ef             	mov    %r13,%rdi
    6822:	e8 00 00 00 00       	callq  6827 <l2cap_ertm_data_rcv+0xc87>
    6827:	e9 b4 f9 ff ff       	jmpq   61e0 <l2cap_ertm_data_rcv+0x640>
		l2cap_send_disconn_req(chan->conn, chan, ECONNRESET);
    682c:	49 8b 7d 08          	mov    0x8(%r13),%rdi
    6830:	ba 68 00 00 00       	mov    $0x68,%edx
    6835:	4c 89 ee             	mov    %r13,%rsi
    6838:	e8 c3 bd ff ff       	callq  2600 <l2cap_send_disconn_req>
    683d:	e9 fe f6 ff ff       	jmpq   5f40 <l2cap_ertm_data_rcv+0x3a0>
	switch (state) {
    6842:	41 0f b6 45 10       	movzbl 0x10(%r13),%eax
    6847:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    684e:	83 e8 01             	sub    $0x1,%eax
    6851:	83 f8 08             	cmp    $0x8,%eax
    6854:	77 08                	ja     685e <l2cap_ertm_data_rcv+0xcbe>
    6856:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    685d:	00 
	BT_DBG("chan %p state %s timeout %ld", chan,
    685e:	4c 8b 45 b8          	mov    -0x48(%rbp),%r8
    6862:	4c 89 ea             	mov    %r13,%rdx
    6865:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    686c:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    6873:	31 c0                	xor    %eax,%eax
    6875:	44 89 5d c0          	mov    %r11d,-0x40(%rbp)
    6879:	e8 00 00 00 00       	callq  687e <l2cap_ertm_data_rcv+0xcde>
    687e:	44 8b 5d c0          	mov    -0x40(%rbp),%r11d
    6882:	e9 1e fa ff ff       	jmpq   62a5 <l2cap_ertm_data_rcv+0x705>
		BT_DBG("chan %p, Enter SREJ", chan);
    6887:	4c 89 ea             	mov    %r13,%rdx
    688a:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    6891:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    6898:	31 c0                	xor    %eax,%eax
    689a:	e8 00 00 00 00       	callq  689f <l2cap_ertm_data_rcv+0xcff>
    689f:	e9 b8 f8 ff ff       	jmpq   615c <l2cap_ertm_data_rcv+0x5bc>
    68a4:	41 0f b6 45 10       	movzbl 0x10(%r13),%eax
    68a9:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    68b0:	83 e8 01             	sub    $0x1,%eax
    68b3:	83 f8 08             	cmp    $0x8,%eax
    68b6:	77 08                	ja     68c0 <l2cap_ertm_data_rcv+0xd20>
    68b8:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    68bf:	00 
    68c0:	49 89 d8             	mov    %rbx,%r8
    68c3:	4c 89 ea             	mov    %r13,%rdx
    68c6:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    68cd:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    68d4:	31 c0                	xor    %eax,%eax
    68d6:	e8 00 00 00 00       	callq  68db <l2cap_ertm_data_rcv+0xd3b>
    68db:	e9 e8 fa ff ff       	jmpq   63c8 <l2cap_ertm_data_rcv+0x828>
	BT_DBG("chan %p len %d tx_seq %d rx_control 0x%8.8x", chan, skb->len,
    68e0:	41 8b 4c 24 68       	mov    0x68(%r12),%ecx
    68e5:	44 0f b7 f3          	movzwl %bx,%r14d
    68e9:	45 89 f9             	mov    %r15d,%r9d
    68ec:	45 89 f0             	mov    %r14d,%r8d
    68ef:	4c 89 ea             	mov    %r13,%rdx
    68f2:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    68f9:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    6900:	31 c0                	xor    %eax,%eax
    6902:	44 89 5d b8          	mov    %r11d,-0x48(%rbp)
    6906:	e8 00 00 00 00       	callq  690b <l2cap_ertm_data_rcv+0xd6b>
    690b:	44 8b 5d b8          	mov    -0x48(%rbp),%r11d
    690f:	e9 75 f4 ff ff       	jmpq   5d89 <l2cap_ertm_data_rcv+0x1e9>
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    6914:	89 d9                	mov    %ebx,%ecx
    6916:	4c 89 e2             	mov    %r12,%rdx
    6919:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    6920:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    6927:	31 c0                	xor    %eax,%eax
    6929:	44 89 4d b8          	mov    %r9d,-0x48(%rbp)
    692d:	e8 00 00 00 00       	callq  6932 <l2cap_ertm_data_rcv+0xd92>
    6932:	44 8b 4d b8          	mov    -0x48(%rbp),%r9d
    6936:	e9 ff fc ff ff       	jmpq   663a <l2cap_ertm_data_rcv+0xa9a>
    693b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000006940 <l2cap_chan_del>:
{
    6940:	55                   	push   %rbp
    6941:	48 89 e5             	mov    %rsp,%rbp
    6944:	41 57                	push   %r15
    6946:	41 56                	push   %r14
    6948:	41 55                	push   %r13
    694a:	41 54                	push   %r12
    694c:	53                   	push   %rbx
    694d:	48 83 ec 18          	sub    $0x18,%rsp
    6951:	e8 00 00 00 00       	callq  6956 <l2cap_chan_del+0x16>
	struct sock *sk = chan->sk;
    6956:	4c 8b 27             	mov    (%rdi),%r12
	struct l2cap_conn *conn = chan->conn;
    6959:	4c 8b 6f 08          	mov    0x8(%rdi),%r13
{
    695d:	48 89 fb             	mov    %rdi,%rbx
	ret = del_timer_sync(&work->timer);
    6960:	48 8d bf 10 01 00 00 	lea    0x110(%rdi),%rdi
    6967:	41 89 f7             	mov    %esi,%r15d
	struct sock *parent = bt_sk(sk)->parent;
    696a:	4d 8b b4 24 a8 02 00 	mov    0x2a8(%r12),%r14
    6971:	00 
    6972:	e8 00 00 00 00       	callq  6977 <l2cap_chan_del+0x37>
	if (ret)
    6977:	85 c0                	test   %eax,%eax
    6979:	74 17                	je     6992 <l2cap_chan_del+0x52>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    697b:	f0 80 a3 f0 00 00 00 	lock andb $0xfe,0xf0(%rbx)
    6982:	fe 
	asm volatile(LOCK_PREFIX "decl %0; sete %1"
    6983:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    6987:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    698a:	84 c0                	test   %al,%al
    698c:	0f 85 7e 02 00 00    	jne    6c10 <l2cap_chan_del+0x2d0>
	BT_DBG("chan %p, conn %p, err %d", chan, conn, err);
    6992:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 6999 <l2cap_chan_del+0x59>
    6999:	0f 85 be 02 00 00    	jne    6c5d <l2cap_chan_del+0x31d>
	if (conn) {
    699f:	4d 85 ed             	test   %r13,%r13
    69a2:	0f 84 98 00 00 00    	je     6a40 <l2cap_chan_del+0x100>
		list_del(&chan->list);
    69a8:	48 8d bb 18 03 00 00 	lea    0x318(%rbx),%rdi
    69af:	e8 00 00 00 00       	callq  69b4 <l2cap_chan_del+0x74>
    69b4:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    69b8:	0f 94 c0             	sete   %al
    69bb:	84 c0                	test   %al,%al
    69bd:	0f 85 fd 00 00 00    	jne    6ac0 <l2cap_chan_del+0x180>
		chan->conn = NULL;
    69c3:	48 c7 43 08 00 00 00 	movq   $0x0,0x8(%rbx)
    69ca:	00 
		hci_conn_put(conn->hcon);
    69cb:	4d 8b 6d 00          	mov    0x0(%r13),%r13
    69cf:	f0 41 ff 4d 10       	lock decl 0x10(%r13)
    69d4:	0f 94 c0             	sete   %al
	cancel_delayed_work(&conn->disc_work);
}

static inline void hci_conn_put(struct hci_conn *conn)
{
	if (atomic_dec_and_test(&conn->refcnt)) {
    69d7:	84 c0                	test   %al,%al
    69d9:	74 65                	je     6a40 <l2cap_chan_del+0x100>
		unsigned long timeo;
		if (conn->type == ACL_LINK || conn->type == LE_LINK) {
    69db:	41 0f b6 45 21       	movzbl 0x21(%r13),%eax
    69e0:	3c 80                	cmp    $0x80,%al
    69e2:	0f 84 e8 01 00 00    	je     6bd0 <l2cap_chan_del+0x290>
    69e8:	3c 01                	cmp    $0x1,%al
    69ea:	0f 84 e0 01 00 00    	je     6bd0 <l2cap_chan_del+0x290>
					timeo *= 2;
			} else {
				timeo = msecs_to_jiffies(10);
			}
		} else {
			timeo = msecs_to_jiffies(10);
    69f0:	bf 0a 00 00 00       	mov    $0xa,%edi
    69f5:	e8 00 00 00 00       	callq  69fa <l2cap_chan_del+0xba>
    69fa:	48 89 c2             	mov    %rax,%rdx
		}
		cancel_delayed_work(&conn->disc_work);
    69fd:	49 8d b5 80 00 00 00 	lea    0x80(%r13),%rsi
	ret = del_timer_sync(&work->timer);
    6a04:	49 8d bd a0 00 00 00 	lea    0xa0(%r13),%rdi
    6a0b:	48 89 55 c0          	mov    %rdx,-0x40(%rbp)
    6a0f:	48 89 75 c8          	mov    %rsi,-0x38(%rbp)
    6a13:	e8 00 00 00 00       	callq  6a18 <l2cap_chan_del+0xd8>
	if (ret)
    6a18:	85 c0                	test   %eax,%eax
    6a1a:	48 8b 75 c8          	mov    -0x38(%rbp),%rsi
    6a1e:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
    6a22:	74 09                	je     6a2d <l2cap_chan_del+0xed>
    6a24:	f0 41 80 a5 80 00 00 	lock andb $0xfe,0x80(%r13)
    6a2b:	00 fe 
		queue_delayed_work(conn->hdev->workqueue,
    6a2d:	49 8b 85 18 04 00 00 	mov    0x418(%r13),%rax
    6a34:	48 8b b8 38 03 00 00 	mov    0x338(%rax),%rdi
    6a3b:	e8 00 00 00 00       	callq  6a40 <l2cap_chan_del+0x100>
    6a40:	31 f6                	xor    %esi,%esi
    6a42:	4c 89 e7             	mov    %r12,%rdi
    6a45:	e8 00 00 00 00       	callq  6a4a <l2cap_chan_del+0x10a>
	__l2cap_state_change(chan, BT_CLOSED);
    6a4a:	be 09 00 00 00       	mov    $0x9,%esi
    6a4f:	48 89 df             	mov    %rbx,%rdi
    6a52:	e8 39 96 ff ff       	callq  90 <__l2cap_state_change>
	asm volatile("bts %1,%0" : ADDR : "Ir" (nr) : "memory");
    6a57:	41 0f ba ac 24 e8 00 	btsl   $0x8,0xe8(%r12)
    6a5e:	00 00 08 
	if (err)
    6a61:	45 85 ff             	test   %r15d,%r15d
    6a64:	74 0a                	je     6a70 <l2cap_chan_del+0x130>
static void l2cap_chan_del(struct l2cap_chan *chan, int err)
    6a66:	48 8b 03             	mov    (%rbx),%rax
	sk->sk_err = err;
    6a69:	44 89 b8 7c 01 00 00 	mov    %r15d,0x17c(%rax)
	if (parent) {
    6a70:	4d 85 f6             	test   %r14,%r14
		bt_accept_unlink(sk);
    6a73:	4c 89 e7             	mov    %r12,%rdi
	if (parent) {
    6a76:	0f 84 a4 01 00 00    	je     6c20 <l2cap_chan_del+0x2e0>
		bt_accept_unlink(sk);
    6a7c:	e8 00 00 00 00       	callq  6a81 <l2cap_chan_del+0x141>
		parent->sk_data_ready(parent, 0);
    6a81:	31 f6                	xor    %esi,%esi
    6a83:	4c 89 f7             	mov    %r14,%rdi
    6a86:	41 ff 96 60 02 00 00 	callq  *0x260(%r14)
	release_sock(sk);
    6a8d:	4c 89 e7             	mov    %r12,%rdi
    6a90:	e8 00 00 00 00       	callq  6a95 <l2cap_chan_del+0x155>
		(addr[nr / BITS_PER_LONG])) != 0;
    6a95:	48 8b 83 80 00 00 00 	mov    0x80(%rbx),%rax
	if (!(test_bit(CONF_OUTPUT_DONE, &chan->conf_state) &&
    6a9c:	a8 04                	test   $0x4,%al
    6a9e:	74 0b                	je     6aab <l2cap_chan_del+0x16b>
    6aa0:	48 8b 83 80 00 00 00 	mov    0x80(%rbx),%rax
    6aa7:	a8 02                	test   $0x2,%al
    6aa9:	75 25                	jne    6ad0 <l2cap_chan_del+0x190>
}
    6aab:	48 83 c4 18          	add    $0x18,%rsp
    6aaf:	5b                   	pop    %rbx
    6ab0:	41 5c                	pop    %r12
    6ab2:	41 5d                	pop    %r13
    6ab4:	41 5e                	pop    %r14
    6ab6:	41 5f                	pop    %r15
    6ab8:	5d                   	pop    %rbp
    6ab9:	c3                   	retq   
    6aba:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		kfree(c);
    6ac0:	48 89 df             	mov    %rbx,%rdi
    6ac3:	e8 00 00 00 00       	callq  6ac8 <l2cap_chan_del+0x188>
    6ac8:	e9 f6 fe ff ff       	jmpq   69c3 <l2cap_chan_del+0x83>
    6acd:	0f 1f 00             	nopl   (%rax)
	skb_queue_purge(&chan->tx_q);
    6ad0:	48 8d bb b8 02 00 00 	lea    0x2b8(%rbx),%rdi
    6ad7:	e8 00 00 00 00       	callq  6adc <l2cap_chan_del+0x19c>
	if (chan->mode == L2CAP_MODE_ERTM) {
    6adc:	80 7b 24 03          	cmpb   $0x3,0x24(%rbx)
    6ae0:	75 c9                	jne    6aab <l2cap_chan_del+0x16b>
	ret = del_timer_sync(&work->timer);
    6ae2:	48 8d bb 80 01 00 00 	lea    0x180(%rbx),%rdi
    6ae9:	e8 00 00 00 00       	callq  6aee <l2cap_chan_del+0x1ae>
	if (ret)
    6aee:	85 c0                	test   %eax,%eax
    6af0:	74 17                	je     6b09 <l2cap_chan_del+0x1c9>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    6af2:	f0 80 a3 60 01 00 00 	lock andb $0xfe,0x160(%rbx)
    6af9:	fe 
    6afa:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    6afe:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    6b01:	84 c0                	test   %al,%al
    6b03:	0f 85 27 01 00 00    	jne    6c30 <l2cap_chan_del+0x2f0>
	ret = del_timer_sync(&work->timer);
    6b09:	48 8d bb f0 01 00 00 	lea    0x1f0(%rbx),%rdi
    6b10:	e8 00 00 00 00       	callq  6b15 <l2cap_chan_del+0x1d5>
	if (ret)
    6b15:	85 c0                	test   %eax,%eax
    6b17:	74 17                	je     6b30 <l2cap_chan_del+0x1f0>
    6b19:	f0 80 a3 d0 01 00 00 	lock andb $0xfe,0x1d0(%rbx)
    6b20:	fe 
    6b21:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    6b25:	0f 94 c0             	sete   %al
    6b28:	84 c0                	test   %al,%al
    6b2a:	0f 85 10 01 00 00    	jne    6c40 <l2cap_chan_del+0x300>
	ret = del_timer_sync(&work->timer);
    6b30:	48 8d bb 60 02 00 00 	lea    0x260(%rbx),%rdi
    6b37:	e8 00 00 00 00       	callq  6b3c <l2cap_chan_del+0x1fc>
	if (ret)
    6b3c:	85 c0                	test   %eax,%eax
    6b3e:	74 17                	je     6b57 <l2cap_chan_del+0x217>
    6b40:	f0 80 a3 40 02 00 00 	lock andb $0xfe,0x240(%rbx)
    6b47:	fe 
    6b48:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    6b4c:	0f 94 c0             	sete   %al
    6b4f:	84 c0                	test   %al,%al
    6b51:	0f 85 f9 00 00 00    	jne    6c50 <l2cap_chan_del+0x310>
		skb_queue_purge(&chan->srej_q);
    6b57:	48 8d bb d0 02 00 00 	lea    0x2d0(%rbx),%rdi
		list_for_each_entry_safe(l, tmp, &chan->srej_l, list) {
    6b5e:	48 81 c3 08 03 00 00 	add    $0x308,%rbx
		skb_queue_purge(&chan->srej_q);
    6b65:	e8 00 00 00 00       	callq  6b6a <l2cap_chan_del+0x22a>
	kfree(seq_list->list);
    6b6a:	48 8b 7b e8          	mov    -0x18(%rbx),%rdi
    6b6e:	e8 00 00 00 00       	callq  6b73 <l2cap_chan_del+0x233>
    6b73:	48 8b 7b f8          	mov    -0x8(%rbx),%rdi
    6b77:	e8 00 00 00 00       	callq  6b7c <l2cap_chan_del+0x23c>
		list_for_each_entry_safe(l, tmp, &chan->srej_l, list) {
    6b7c:	48 8b 03             	mov    (%rbx),%rax
    6b7f:	48 8b 08             	mov    (%rax),%rcx
    6b82:	48 39 d8             	cmp    %rbx,%rax
    6b85:	4c 8d 68 f8          	lea    -0x8(%rax),%r13
    6b89:	48 89 c7             	mov    %rax,%rdi
    6b8c:	4c 8d 61 f8          	lea    -0x8(%rcx),%r12
    6b90:	75 14                	jne    6ba6 <l2cap_chan_del+0x266>
    6b92:	e9 14 ff ff ff       	jmpq   6aab <l2cap_chan_del+0x16b>
    6b97:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    6b9e:	00 00 
    6ba0:	4d 89 e5             	mov    %r12,%r13
    6ba3:	49 89 d4             	mov    %rdx,%r12
			list_del(&l->list);
    6ba6:	e8 00 00 00 00       	callq  6bab <l2cap_chan_del+0x26b>
			kfree(l);
    6bab:	4c 89 ef             	mov    %r13,%rdi
    6bae:	e8 00 00 00 00       	callq  6bb3 <l2cap_chan_del+0x273>
		list_for_each_entry_safe(l, tmp, &chan->srej_l, list) {
    6bb3:	49 8b 44 24 08       	mov    0x8(%r12),%rax
    6bb8:	49 8d 7c 24 08       	lea    0x8(%r12),%rdi
    6bbd:	48 39 df             	cmp    %rbx,%rdi
    6bc0:	48 8d 50 f8          	lea    -0x8(%rax),%rdx
    6bc4:	75 da                	jne    6ba0 <l2cap_chan_del+0x260>
    6bc6:	e9 e0 fe ff ff       	jmpq   6aab <l2cap_chan_del+0x16b>
    6bcb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
			del_timer(&conn->idle_timer);
    6bd0:	49 8d bd f0 00 00 00 	lea    0xf0(%r13),%rdi
    6bd7:	e8 00 00 00 00       	callq  6bdc <l2cap_chan_del+0x29c>
			if (conn->state == BT_CONNECTED) {
    6bdc:	66 41 83 7d 1e 01    	cmpw   $0x1,0x1e(%r13)
    6be2:	0f 85 08 fe ff ff    	jne    69f0 <l2cap_chan_del+0xb0>
				timeo = msecs_to_jiffies(conn->disc_timeout);
    6be8:	41 0f b7 7d 44       	movzwl 0x44(%r13),%edi
    6bed:	e8 00 00 00 00       	callq  6bf2 <l2cap_chan_del+0x2b2>
					timeo *= 2;
    6bf2:	41 80 7d 22 00       	cmpb   $0x0,0x22(%r13)
				timeo = msecs_to_jiffies(conn->disc_timeout);
    6bf7:	48 89 c2             	mov    %rax,%rdx
					timeo *= 2;
    6bfa:	48 8d 04 00          	lea    (%rax,%rax,1),%rax
    6bfe:	48 0f 44 d0          	cmove  %rax,%rdx
    6c02:	e9 f6 fd ff ff       	jmpq   69fd <l2cap_chan_del+0xbd>
    6c07:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    6c0e:	00 00 
		kfree(c);
    6c10:	48 89 df             	mov    %rbx,%rdi
    6c13:	e8 00 00 00 00       	callq  6c18 <l2cap_chan_del+0x2d8>
    6c18:	e9 75 fd ff ff       	jmpq   6992 <l2cap_chan_del+0x52>
    6c1d:	0f 1f 00             	nopl   (%rax)
		sk->sk_state_change(sk);
    6c20:	41 ff 94 24 58 02 00 	callq  *0x258(%r12)
    6c27:	00 
    6c28:	e9 60 fe ff ff       	jmpq   6a8d <l2cap_chan_del+0x14d>
    6c2d:	0f 1f 00             	nopl   (%rax)
    6c30:	48 89 df             	mov    %rbx,%rdi
    6c33:	e8 00 00 00 00       	callq  6c38 <l2cap_chan_del+0x2f8>
    6c38:	e9 cc fe ff ff       	jmpq   6b09 <l2cap_chan_del+0x1c9>
    6c3d:	0f 1f 00             	nopl   (%rax)
    6c40:	48 89 df             	mov    %rbx,%rdi
    6c43:	e8 00 00 00 00       	callq  6c48 <l2cap_chan_del+0x308>
    6c48:	e9 e3 fe ff ff       	jmpq   6b30 <l2cap_chan_del+0x1f0>
    6c4d:	0f 1f 00             	nopl   (%rax)
    6c50:	48 89 df             	mov    %rbx,%rdi
    6c53:	e8 00 00 00 00       	callq  6c58 <l2cap_chan_del+0x318>
    6c58:	e9 fa fe ff ff       	jmpq   6b57 <l2cap_chan_del+0x217>
	BT_DBG("chan %p, conn %p, err %d", chan, conn, err);
    6c5d:	45 89 f8             	mov    %r15d,%r8d
    6c60:	4c 89 e9             	mov    %r13,%rcx
    6c63:	48 89 da             	mov    %rbx,%rdx
    6c66:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    6c6d:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    6c74:	31 c0                	xor    %eax,%eax
    6c76:	e8 00 00 00 00       	callq  6c7b <l2cap_chan_del+0x33b>
    6c7b:	e9 1f fd ff ff       	jmpq   699f <l2cap_chan_del+0x5f>

0000000000006c80 <l2cap_connect_rsp>:
{
    6c80:	55                   	push   %rbp
    6c81:	48 89 e5             	mov    %rsp,%rbp
    6c84:	41 57                	push   %r15
    6c86:	41 56                	push   %r14
    6c88:	41 55                	push   %r13
    6c8a:	49 89 f5             	mov    %rsi,%r13
    6c8d:	41 54                	push   %r12
    6c8f:	53                   	push   %rbx
    6c90:	48 89 fb             	mov    %rdi,%rbx
    6c93:	48 81 ec a8 00 00 00 	sub    $0xa8,%rsp
	scid   = __le16_to_cpu(rsp->scid);
    6c9a:	44 0f b7 52 02       	movzwl 0x2(%rdx),%r10d
	result = __le16_to_cpu(rsp->result);
    6c9f:	44 0f b7 72 04       	movzwl 0x4(%rdx),%r14d
{
    6ca4:	65 48 8b 04 25 28 00 	mov    %gs:0x28,%rax
    6cab:	00 00 
    6cad:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    6cb1:	31 c0                	xor    %eax,%eax
	dcid   = __le16_to_cpu(rsp->dcid);
    6cb3:	0f b7 02             	movzwl (%rdx),%eax
	BT_DBG("dcid 0x%4.4x scid 0x%4.4x result 0x%2.2x status 0x%2.2x",
    6cb6:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 6cbd <l2cap_connect_rsp+0x3d>
	status = __le16_to_cpu(rsp->status);
    6cbd:	44 0f b7 4a 06       	movzwl 0x6(%rdx),%r9d
	dcid   = __le16_to_cpu(rsp->dcid);
    6cc2:	66 89 85 3a ff ff ff 	mov    %ax,-0xc6(%rbp)
	BT_DBG("dcid 0x%4.4x scid 0x%4.4x result 0x%2.2x status 0x%2.2x",
    6cc9:	0f 85 f8 01 00 00    	jne    6ec7 <l2cap_connect_rsp+0x247>
	mutex_lock(&conn->chan_lock);
    6ccf:	4c 8d a3 40 01 00 00 	lea    0x140(%rbx),%r12
    6cd6:	44 89 95 3c ff ff ff 	mov    %r10d,-0xc4(%rbp)
    6cdd:	4c 89 e7             	mov    %r12,%rdi
    6ce0:	e8 00 00 00 00       	callq  6ce5 <l2cap_connect_rsp+0x65>
	if (scid) {
    6ce5:	44 8b 95 3c ff ff ff 	mov    -0xc4(%rbp),%r10d
    6cec:	66 45 85 d2          	test   %r10w,%r10w
    6cf0:	0f 84 ca 00 00 00    	je     6dc0 <l2cap_connect_rsp+0x140>
	list_for_each_entry(c, &conn->chan_l, list) {
    6cf6:	48 8b 83 30 01 00 00 	mov    0x130(%rbx),%rax
    6cfd:	48 8d 93 30 01 00 00 	lea    0x130(%rbx),%rdx
			err = -EFAULT;
    6d04:	41 bd f2 ff ff ff    	mov    $0xfffffff2,%r13d
	list_for_each_entry(c, &conn->chan_l, list) {
    6d0a:	48 39 c2             	cmp    %rax,%rdx
    6d0d:	4c 8d b8 e8 fc ff ff 	lea    -0x318(%rax),%r15
    6d14:	75 51                	jne    6d67 <l2cap_connect_rsp+0xe7>
    6d16:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    6d1d:	00 00 00 
	mutex_unlock(&conn->chan_lock);
    6d20:	4c 89 e7             	mov    %r12,%rdi
    6d23:	e8 00 00 00 00       	callq  6d28 <l2cap_connect_rsp+0xa8>
}
    6d28:	48 8b 75 c8          	mov    -0x38(%rbp),%rsi
    6d2c:	65 48 33 34 25 28 00 	xor    %gs:0x28,%rsi
    6d33:	00 00 
    6d35:	44 89 e8             	mov    %r13d,%eax
    6d38:	0f 85 84 01 00 00    	jne    6ec2 <l2cap_connect_rsp+0x242>
    6d3e:	48 81 c4 a8 00 00 00 	add    $0xa8,%rsp
    6d45:	5b                   	pop    %rbx
    6d46:	41 5c                	pop    %r12
    6d48:	41 5d                	pop    %r13
    6d4a:	41 5e                	pop    %r14
    6d4c:	41 5f                	pop    %r15
    6d4e:	5d                   	pop    %rbp
    6d4f:	c3                   	retq   
	list_for_each_entry(c, &conn->chan_l, list) {
    6d50:	49 8b 87 18 03 00 00 	mov    0x318(%r15),%rax
    6d57:	48 39 c2             	cmp    %rax,%rdx
    6d5a:	4c 8d b8 e8 fc ff ff 	lea    -0x318(%rax),%r15
    6d61:	0f 84 b9 00 00 00    	je     6e20 <l2cap_connect_rsp+0x1a0>
		if (c->scid == cid)
    6d67:	66 44 3b 90 04 fd ff 	cmp    -0x2fc(%rax),%r10w
    6d6e:	ff 
    6d6f:	75 df                	jne    6d50 <l2cap_connect_rsp+0xd0>
		if (!chan) {
    6d71:	4d 85 ff             	test   %r15,%r15
    6d74:	0f 84 a6 00 00 00    	je     6e20 <l2cap_connect_rsp+0x1a0>
	mutex_lock(&chan->lock);
    6d7a:	4d 8d af 48 03 00 00 	lea    0x348(%r15),%r13
    6d81:	4c 89 ef             	mov    %r13,%rdi
    6d84:	e8 00 00 00 00       	callq  6d89 <l2cap_connect_rsp+0x109>
	switch (result) {
    6d89:	66 45 85 f6          	test   %r14w,%r14w
    6d8d:	0f 84 b5 00 00 00    	je     6e48 <l2cap_connect_rsp+0x1c8>
    6d93:	66 41 83 fe 01       	cmp    $0x1,%r14w
    6d98:	0f 85 92 00 00 00    	jne    6e30 <l2cap_connect_rsp+0x1b0>
		asm volatile(LOCK_PREFIX "orb %1,%0"
    6d9e:	f0 41 80 8f 80 00 00 	lock orb $0x20,0x80(%r15)
    6da5:	00 20 
	mutex_unlock(&chan->lock);
    6da7:	4c 89 ef             	mov    %r13,%rdi
	err = 0;
    6daa:	45 31 ed             	xor    %r13d,%r13d
    6dad:	e8 00 00 00 00       	callq  6db2 <l2cap_connect_rsp+0x132>
    6db2:	e9 69 ff ff ff       	jmpq   6d20 <l2cap_connect_rsp+0xa0>
    6db7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    6dbe:	00 00 
	list_for_each_entry(c, &conn->chan_l, list) {
    6dc0:	48 8b 83 30 01 00 00 	mov    0x130(%rbx),%rax
    6dc7:	48 8d 93 30 01 00 00 	lea    0x130(%rbx),%rdx
		chan = __l2cap_get_chan_by_ident(conn, cmd->ident);
    6dce:	41 0f b6 4d 01       	movzbl 0x1(%r13),%ecx
			err = -EFAULT;
    6dd3:	41 bd f2 ff ff ff    	mov    $0xfffffff2,%r13d
	list_for_each_entry(c, &conn->chan_l, list) {
    6dd9:	48 39 c2             	cmp    %rax,%rdx
    6ddc:	4c 8d b8 e8 fc ff ff 	lea    -0x318(%rax),%r15
    6de3:	0f 84 37 ff ff ff    	je     6d20 <l2cap_connect_rsp+0xa0>
		if (c->ident == ident)
    6de9:	3a 88 13 fd ff ff    	cmp    -0x2ed(%rax),%cl
    6def:	74 80                	je     6d71 <l2cap_connect_rsp+0xf1>
    6df1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
	list_for_each_entry(c, &conn->chan_l, list) {
    6df8:	49 8b 87 18 03 00 00 	mov    0x318(%r15),%rax
    6dff:	48 39 c2             	cmp    %rax,%rdx
    6e02:	4c 8d b8 e8 fc ff ff 	lea    -0x318(%rax),%r15
    6e09:	74 15                	je     6e20 <l2cap_connect_rsp+0x1a0>
		if (c->ident == ident)
    6e0b:	3a 88 13 fd ff ff    	cmp    -0x2ed(%rax),%cl
    6e11:	75 e5                	jne    6df8 <l2cap_connect_rsp+0x178>
    6e13:	e9 59 ff ff ff       	jmpq   6d71 <l2cap_connect_rsp+0xf1>
    6e18:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    6e1f:	00 
			err = -EFAULT;
    6e20:	41 bd f2 ff ff ff    	mov    $0xfffffff2,%r13d
    6e26:	e9 f5 fe ff ff       	jmpq   6d20 <l2cap_connect_rsp+0xa0>
    6e2b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		l2cap_chan_del(chan, ECONNREFUSED);
    6e30:	be 6f 00 00 00       	mov    $0x6f,%esi
    6e35:	4c 89 ff             	mov    %r15,%rdi
    6e38:	e8 03 fb ff ff       	callq  6940 <l2cap_chan_del>
		break;
    6e3d:	e9 65 ff ff ff       	jmpq   6da7 <l2cap_connect_rsp+0x127>
    6e42:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		l2cap_state_change(chan, BT_CONFIG);
    6e48:	be 07 00 00 00       	mov    $0x7,%esi
    6e4d:	4c 89 ff             	mov    %r15,%rdi
    6e50:	e8 cb 98 ff ff       	callq  720 <l2cap_state_change>
		chan->dcid = dcid;
    6e55:	0f b7 85 3a ff ff ff 	movzwl -0xc6(%rbp),%eax
		chan->ident = 0;
    6e5c:	41 c6 47 2b 00       	movb   $0x0,0x2b(%r15)
		chan->dcid = dcid;
    6e61:	66 41 89 47 1a       	mov    %ax,0x1a(%r15)
		asm volatile(LOCK_PREFIX "andb %1,%0"
    6e66:	f0 41 80 a7 80 00 00 	lock andb $0xdf,0x80(%r15)
    6e6d:	00 df 
	asm volatile(LOCK_PREFIX "bts %2,%1\n\t"
    6e6f:	f0 41 0f ba af 80 00 	lock btsl $0x0,0x80(%r15)
    6e76:	00 00 00 
    6e79:	19 c0                	sbb    %eax,%eax
		if (test_and_set_bit(CONF_REQ_SENT, &chan->conf_state))
    6e7b:	85 c0                	test   %eax,%eax
    6e7d:	0f 85 24 ff ff ff    	jne    6da7 <l2cap_connect_rsp+0x127>
					l2cap_build_conf_req(chan, req), req);
    6e83:	48 8d b5 48 ff ff ff 	lea    -0xb8(%rbp),%rsi
    6e8a:	4c 89 ff             	mov    %r15,%rdi
    6e8d:	e8 de a7 ff ff       	callq  1670 <l2cap_build_conf_req>
		l2cap_send_cmd(conn, l2cap_get_ident(conn), L2CAP_CONF_REQ,
    6e92:	48 89 df             	mov    %rbx,%rdi
					l2cap_build_conf_req(chan, req), req);
    6e95:	41 89 c6             	mov    %eax,%r14d
		l2cap_send_cmd(conn, l2cap_get_ident(conn), L2CAP_CONF_REQ,
    6e98:	e8 13 96 ff ff       	callq  4b0 <l2cap_get_ident>
    6e9d:	4c 8d 85 48 ff ff ff 	lea    -0xb8(%rbp),%r8
    6ea4:	41 0f b7 ce          	movzwl %r14w,%ecx
    6ea8:	0f b6 f0             	movzbl %al,%esi
    6eab:	ba 04 00 00 00       	mov    $0x4,%edx
    6eb0:	48 89 df             	mov    %rbx,%rdi
    6eb3:	e8 08 a5 ff ff       	callq  13c0 <l2cap_send_cmd>
		chan->num_conf_req++;
    6eb8:	41 80 47 6d 01       	addb   $0x1,0x6d(%r15)
		break;
    6ebd:	e9 e5 fe ff ff       	jmpq   6da7 <l2cap_connect_rsp+0x127>
}
    6ec2:	e8 00 00 00 00       	callq  6ec7 <l2cap_connect_rsp+0x247>
	BT_DBG("dcid 0x%4.4x scid 0x%4.4x result 0x%2.2x status 0x%2.2x",
    6ec7:	41 0f b7 ca          	movzwl %r10w,%ecx
    6ecb:	0f b7 d0             	movzwl %ax,%edx
    6ece:	45 0f b7 c6          	movzwl %r14w,%r8d
    6ed2:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    6ed9:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    6ee0:	31 c0                	xor    %eax,%eax
    6ee2:	44 89 95 3c ff ff ff 	mov    %r10d,-0xc4(%rbp)
    6ee9:	e8 00 00 00 00       	callq  6eee <l2cap_connect_rsp+0x26e>
    6eee:	44 8b 95 3c ff ff ff 	mov    -0xc4(%rbp),%r10d
    6ef5:	e9 d5 fd ff ff       	jmpq   6ccf <l2cap_connect_rsp+0x4f>
    6efa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000006f00 <l2cap_conn_del>:
{
    6f00:	55                   	push   %rbp
    6f01:	48 89 e5             	mov    %rsp,%rbp
    6f04:	41 57                	push   %r15
    6f06:	41 56                	push   %r14
    6f08:	41 55                	push   %r13
    6f0a:	41 54                	push   %r12
    6f0c:	53                   	push   %rbx
    6f0d:	48 83 ec 28          	sub    $0x28,%rsp
    6f11:	e8 00 00 00 00       	callq  6f16 <l2cap_conn_del+0x16>
	struct l2cap_conn *conn = hcon->l2cap_data;
    6f16:	4c 8b af 20 04 00 00 	mov    0x420(%rdi),%r13
{
    6f1d:	48 89 7d c0          	mov    %rdi,-0x40(%rbp)
    6f21:	89 75 cc             	mov    %esi,-0x34(%rbp)
	if (!conn)
    6f24:	4d 85 ed             	test   %r13,%r13
    6f27:	0f 84 ff 00 00 00    	je     702c <l2cap_conn_del+0x12c>
	BT_DBG("hcon %p conn %p, err %d", hcon, conn, err);
    6f2d:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 6f34 <l2cap_conn_del+0x34>
    6f34:	0f 85 2c 01 00 00    	jne    7066 <l2cap_conn_del+0x166>
	kfree_skb(conn->rx_skb);
    6f3a:	49 8b bd a8 00 00 00 	mov    0xa8(%r13),%rdi
	list_for_each_entry_safe(chan, l, &conn->chan_l, list) {
    6f41:	49 8d 9d 30 01 00 00 	lea    0x130(%r13),%rbx
	kfree_skb(conn->rx_skb);
    6f48:	e8 00 00 00 00       	callq  6f4d <l2cap_conn_del+0x4d>
	mutex_lock(&conn->chan_lock);
    6f4d:	49 8d 85 40 01 00 00 	lea    0x140(%r13),%rax
    6f54:	48 89 c7             	mov    %rax,%rdi
    6f57:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    6f5b:	e8 00 00 00 00       	callq  6f60 <l2cap_conn_del+0x60>
	list_for_each_entry_safe(chan, l, &conn->chan_l, list) {
    6f60:	49 8b 8d 30 01 00 00 	mov    0x130(%r13),%rcx
    6f67:	48 8b 01             	mov    (%rcx),%rax
    6f6a:	48 39 cb             	cmp    %rcx,%rbx
    6f6d:	4c 8d b1 e8 fc ff ff 	lea    -0x318(%rcx),%r14
    6f74:	4c 8d b8 e8 fc ff ff 	lea    -0x318(%rax),%r15
    6f7b:	75 09                	jne    6f86 <l2cap_conn_del+0x86>
    6f7d:	eb 6d                	jmp    6fec <l2cap_conn_del+0xec>
    6f7f:	90                   	nop
    6f80:	4d 89 fe             	mov    %r15,%r14
    6f83:	49 89 cf             	mov    %rcx,%r15
	asm volatile(LOCK_PREFIX "incl %0"
    6f86:	f0 41 ff 46 14       	lock incl 0x14(%r14)
	mutex_lock(&chan->lock);
    6f8b:	4d 8d a6 48 03 00 00 	lea    0x348(%r14),%r12
    6f92:	4c 89 e7             	mov    %r12,%rdi
    6f95:	e8 00 00 00 00       	callq  6f9a <l2cap_conn_del+0x9a>
		l2cap_chan_del(chan, err);
    6f9a:	8b 75 cc             	mov    -0x34(%rbp),%esi
    6f9d:	4c 89 f7             	mov    %r14,%rdi
    6fa0:	e8 9b f9 ff ff       	callq  6940 <l2cap_chan_del>
	mutex_unlock(&chan->lock);
    6fa5:	4c 89 e7             	mov    %r12,%rdi
    6fa8:	e8 00 00 00 00       	callq  6fad <l2cap_conn_del+0xad>
		chan->ops->close(chan->data);
    6fad:	49 8b 8e 40 03 00 00 	mov    0x340(%r14),%rcx
    6fb4:	49 8b be 38 03 00 00 	mov    0x338(%r14),%rdi
    6fbb:	ff 51 18             	callq  *0x18(%rcx)
	asm volatile(LOCK_PREFIX "decl %0; sete %1"
    6fbe:	f0 41 ff 4e 14       	lock decl 0x14(%r14)
    6fc3:	0f 94 c1             	sete   %cl
	if (atomic_dec_and_test(&c->refcnt))
    6fc6:	84 c9                	test   %cl,%cl
    6fc8:	74 08                	je     6fd2 <l2cap_conn_del+0xd2>
		kfree(c);
    6fca:	4c 89 f7             	mov    %r14,%rdi
    6fcd:	e8 00 00 00 00       	callq  6fd2 <l2cap_conn_del+0xd2>
	list_for_each_entry_safe(chan, l, &conn->chan_l, list) {
    6fd2:	49 8b 87 18 03 00 00 	mov    0x318(%r15),%rax
    6fd9:	48 8d 88 e8 fc ff ff 	lea    -0x318(%rax),%rcx
    6fe0:	49 8d 87 18 03 00 00 	lea    0x318(%r15),%rax
    6fe7:	48 39 c3             	cmp    %rax,%rbx
    6fea:	75 94                	jne    6f80 <l2cap_conn_del+0x80>
	mutex_unlock(&conn->chan_lock);
    6fec:	48 8b 7d b8          	mov    -0x48(%rbp),%rdi
    6ff0:	e8 00 00 00 00       	callq  6ff5 <l2cap_conn_del+0xf5>
	hci_chan_del(conn->hchan);
    6ff5:	49 8b 7d 08          	mov    0x8(%r13),%rdi
    6ff9:	e8 00 00 00 00       	callq  6ffe <l2cap_conn_del+0xfe>
	if (conn->info_state & L2CAP_INFO_FEAT_MASK_REQ_SENT)
    6ffe:	41 f6 45 29 04       	testb  $0x4,0x29(%r13)
    7003:	75 3b                	jne    7040 <l2cap_conn_del+0x140>
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    7005:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    7009:	f0 0f ba 70 48 06    	lock btrl $0x6,0x48(%rax)
    700f:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(HCI_CONN_LE_SMP_PEND, &hcon->flags)) {
    7011:	85 c0                	test   %eax,%eax
    7013:	75 3b                	jne    7050 <l2cap_conn_del+0x150>
	hcon->l2cap_data = NULL;
    7015:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
	kfree(conn);
    7019:	4c 89 ef             	mov    %r13,%rdi
	hcon->l2cap_data = NULL;
    701c:	48 c7 80 20 04 00 00 	movq   $0x0,0x420(%rax)
    7023:	00 00 00 00 
	kfree(conn);
    7027:	e8 00 00 00 00       	callq  702c <l2cap_conn_del+0x12c>
}
    702c:	48 83 c4 28          	add    $0x28,%rsp
    7030:	5b                   	pop    %rbx
    7031:	41 5c                	pop    %r12
    7033:	41 5d                	pop    %r13
    7035:	41 5e                	pop    %r14
    7037:	41 5f                	pop    %r15
    7039:	5d                   	pop    %rbp
    703a:	c3                   	retq   
    703b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		cancel_delayed_work_sync(&conn->info_timer);
    7040:	49 8d 7d 30          	lea    0x30(%r13),%rdi
    7044:	e8 00 00 00 00       	callq  7049 <l2cap_conn_del+0x149>
    7049:	eb ba                	jmp    7005 <l2cap_conn_del+0x105>
    704b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		cancel_delayed_work_sync(&conn->security_timer);
    7050:	49 8d bd b8 00 00 00 	lea    0xb8(%r13),%rdi
    7057:	e8 00 00 00 00       	callq  705c <l2cap_conn_del+0x15c>
		smp_chan_destroy(conn);
    705c:	4c 89 ef             	mov    %r13,%rdi
    705f:	e8 00 00 00 00       	callq  7064 <l2cap_conn_del+0x164>
    7064:	eb af                	jmp    7015 <l2cap_conn_del+0x115>
	BT_DBG("hcon %p conn %p, err %d", hcon, conn, err);
    7066:	41 89 f0             	mov    %esi,%r8d
    7069:	48 89 fa             	mov    %rdi,%rdx
    706c:	4c 89 e9             	mov    %r13,%rcx
    706f:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    7076:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    707d:	31 c0                	xor    %eax,%eax
    707f:	e8 00 00 00 00       	callq  7084 <l2cap_conn_del+0x184>
    7084:	e9 b1 fe ff ff       	jmpq   6f3a <l2cap_conn_del+0x3a>
    7089:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000007090 <security_timeout>:
{
    7090:	55                   	push   %rbp
    7091:	48 89 e5             	mov    %rsp,%rbp
    7094:	e8 00 00 00 00       	callq  7099 <security_timeout+0x9>
	l2cap_conn_del(conn->hcon, ETIMEDOUT);
    7099:	48 8b bf 48 ff ff ff 	mov    -0xb8(%rdi),%rdi
    70a0:	be 6e 00 00 00       	mov    $0x6e,%esi
    70a5:	e8 56 fe ff ff       	callq  6f00 <l2cap_conn_del>
}
    70aa:	5d                   	pop    %rbp
    70ab:	c3                   	retq   
    70ac:	0f 1f 40 00          	nopl   0x0(%rax)

00000000000070b0 <l2cap_add_psm>:
{
    70b0:	55                   	push   %rbp
    70b1:	48 89 e5             	mov    %rsp,%rbp
    70b4:	41 56                	push   %r14
    70b6:	41 55                	push   %r13
    70b8:	41 54                	push   %r12
    70ba:	53                   	push   %rbx
    70bb:	e8 00 00 00 00       	callq  70c0 <l2cap_add_psm+0x10>
	if (psm && __l2cap_global_chan_by_addr(psm, src)) {
    70c0:	bb 01 10 00 00       	mov    $0x1001,%ebx
{
    70c5:	41 89 d5             	mov    %edx,%r13d
    70c8:	49 89 fe             	mov    %rdi,%r14
	write_lock(&chan_list_lock);
    70cb:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
{
    70d2:	49 89 f4             	mov    %rsi,%r12
	write_lock(&chan_list_lock);
    70d5:	e8 00 00 00 00       	callq  70da <l2cap_add_psm+0x2a>
	if (psm && __l2cap_global_chan_by_addr(psm, src)) {
    70da:	66 45 85 ed          	test   %r13w,%r13w
    70de:	74 13                	je     70f3 <l2cap_add_psm+0x43>
    70e0:	eb 3e                	jmp    7120 <l2cap_add_psm+0x70>
    70e2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    70e8:	83 c3 02             	add    $0x2,%ebx
		for (p = 0x1001; p < 0x1100; p += 2)
    70eb:	81 fb 01 11 00 00    	cmp    $0x1101,%ebx
    70f1:	74 5d                	je     7150 <l2cap_add_psm+0xa0>
			if (!__l2cap_global_chan_by_addr(cpu_to_le16(p), src)) {
    70f3:	4c 89 e6             	mov    %r12,%rsi
    70f6:	89 df                	mov    %ebx,%edi
    70f8:	e8 03 8f ff ff       	callq  0 <__l2cap_global_chan_by_addr>
    70fd:	48 85 c0             	test   %rax,%rax
    7100:	75 e6                	jne    70e8 <l2cap_add_psm+0x38>
				chan->psm   = cpu_to_le16(p);
    7102:	66 41 89 5e 18       	mov    %bx,0x18(%r14)
				chan->sport = cpu_to_le16(p);
    7107:	66 41 89 5e 28       	mov    %bx,0x28(%r14)
		     :"+m" (rw->lock) : : "memory");
}

static inline void arch_write_unlock(arch_rwlock_t *rw)
{
	asm volatile(LOCK_PREFIX WRITE_LOCK_ADD(%1) "%0"
    710c:	f0 81 05 00 00 00 00 	lock addl $0x100000,0x0(%rip)        # 7117 <l2cap_add_psm+0x67>
    7113:	00 00 10 00 
}
    7117:	5b                   	pop    %rbx
    7118:	41 5c                	pop    %r12
    711a:	41 5d                	pop    %r13
    711c:	41 5e                	pop    %r14
    711e:	5d                   	pop    %rbp
    711f:	c3                   	retq   
	if (psm && __l2cap_global_chan_by_addr(psm, src)) {
    7120:	41 0f b7 fd          	movzwl %r13w,%edi
    7124:	4c 89 e6             	mov    %r12,%rsi
    7127:	e8 d4 8e ff ff       	callq  0 <__l2cap_global_chan_by_addr>
    712c:	48 89 c2             	mov    %rax,%rdx
		err = -EADDRINUSE;
    712f:	b8 9e ff ff ff       	mov    $0xffffff9e,%eax
	if (psm && __l2cap_global_chan_by_addr(psm, src)) {
    7134:	48 85 d2             	test   %rdx,%rdx
    7137:	75 d3                	jne    710c <l2cap_add_psm+0x5c>
		chan->psm = psm;
    7139:	66 45 89 6e 18       	mov    %r13w,0x18(%r14)
		chan->sport = psm;
    713e:	66 45 89 6e 28       	mov    %r13w,0x28(%r14)
		err = 0;
    7143:	31 c0                	xor    %eax,%eax
    7145:	eb c5                	jmp    710c <l2cap_add_psm+0x5c>
    7147:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    714e:	00 00 
		err = -EINVAL;
    7150:	b8 ea ff ff ff       	mov    $0xffffffea,%eax
    7155:	eb b5                	jmp    710c <l2cap_add_psm+0x5c>
    7157:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    715e:	00 00 

0000000000007160 <l2cap_add_scid>:
{
    7160:	55                   	push   %rbp
    7161:	48 89 e5             	mov    %rsp,%rbp
    7164:	41 54                	push   %r12
    7166:	53                   	push   %rbx
    7167:	e8 00 00 00 00       	callq  716c <l2cap_add_scid+0xc>
    716c:	48 89 fb             	mov    %rdi,%rbx
    716f:	41 89 f4             	mov    %esi,%r12d
	write_lock(&chan_list_lock);
    7172:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    7179:	e8 00 00 00 00       	callq  717e <l2cap_add_scid+0x1e>
	chan->scid = scid;
    717e:	66 44 89 63 1c       	mov    %r12w,0x1c(%rbx)
    7183:	f0 81 05 00 00 00 00 	lock addl $0x100000,0x0(%rip)        # 718e <l2cap_add_scid+0x2e>
    718a:	00 00 10 00 
}
    718e:	5b                   	pop    %rbx
    718f:	41 5c                	pop    %r12
    7191:	31 c0                	xor    %eax,%eax
    7193:	5d                   	pop    %rbp
    7194:	c3                   	retq   
    7195:	90                   	nop
    7196:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    719d:	00 00 00 

00000000000071a0 <l2cap_chan_create>:
{
    71a0:	55                   	push   %rbp
    71a1:	48 89 e5             	mov    %rsp,%rbp
    71a4:	53                   	push   %rbx
    71a5:	48 83 ec 08          	sub    $0x8,%rsp
    71a9:	e8 00 00 00 00       	callq  71ae <l2cap_chan_create+0xe>
	return kmalloc_caches[index];
    71ae:	48 8b 3d 00 00 00 00 	mov    0x0(%rip),%rdi        # 71b5 <l2cap_chan_create+0x15>
			if (!s)
    71b5:	48 85 ff             	test   %rdi,%rdi
    71b8:	0f 84 c2 00 00 00    	je     7280 <l2cap_chan_create+0xe0>
			return kmem_cache_alloc_trace(s, flags, size);
    71be:	ba 68 03 00 00       	mov    $0x368,%edx
    71c3:	be 20 80 00 00       	mov    $0x8020,%esi
    71c8:	e8 00 00 00 00       	callq  71cd <l2cap_chan_create+0x2d>
	if (!chan)
    71cd:	48 85 c0             	test   %rax,%rax
    71d0:	48 89 c3             	mov    %rax,%rbx
    71d3:	0f 84 b7 00 00 00    	je     7290 <l2cap_chan_create+0xf0>
	mutex_init(&chan->lock);
    71d9:	48 8d bb 48 03 00 00 	lea    0x348(%rbx),%rdi
    71e0:	48 c7 c2 00 00 00 00 	mov    $0x0,%rdx
    71e7:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    71ee:	e8 00 00 00 00       	callq  71f3 <l2cap_chan_create+0x53>
	write_lock(&chan_list_lock);
    71f3:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    71fa:	e8 00 00 00 00       	callq  71ff <l2cap_chan_create+0x5f>
	__list_add(new, head, head->next);
    71ff:	48 8b 15 00 00 00 00 	mov    0x0(%rip),%rdx        # 7206 <l2cap_chan_create+0x66>
	list_add(&chan->global_l, &chan_list);
    7206:	48 8d bb 28 03 00 00 	lea    0x328(%rbx),%rdi
    720d:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    7214:	e8 00 00 00 00       	callq  7219 <l2cap_chan_create+0x79>
    7219:	f0 81 05 00 00 00 00 	lock addl $0x100000,0x0(%rip)        # 7224 <l2cap_chan_create+0x84>
    7220:	00 00 10 00 
	INIT_DELAYED_WORK(&chan->chan_timer, l2cap_chan_timeout);
    7224:	48 8d 83 f8 00 00 00 	lea    0xf8(%rbx),%rax
    722b:	48 8d bb 10 01 00 00 	lea    0x110(%rbx),%rdi
    7232:	31 d2                	xor    %edx,%edx
    7234:	31 f6                	xor    %esi,%esi
    7236:	48 c7 83 f0 00 00 00 	movq   $0x900,0xf0(%rbx)
    723d:	00 09 00 00 
    7241:	48 c7 83 08 01 00 00 	movq   $0x0,0x108(%rbx)
    7248:	00 00 00 00 
	list->next = list;
    724c:	48 89 83 f8 00 00 00 	mov    %rax,0xf8(%rbx)
	list->prev = list;
    7253:	48 89 83 00 01 00 00 	mov    %rax,0x100(%rbx)
    725a:	e8 00 00 00 00       	callq  725f <l2cap_chan_create+0xbf>
	chan->state = BT_OPEN;
    725f:	c6 43 10 02          	movb   $0x2,0x10(%rbx)
	v->counter = i;
    7263:	c7 43 14 01 00 00 00 	movl   $0x1,0x14(%rbx)
	BT_DBG("chan %p", chan);
    726a:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 7271 <l2cap_chan_create+0xd1>
    7271:	75 21                	jne    7294 <l2cap_chan_create+0xf4>
    7273:	48 89 d8             	mov    %rbx,%rax
}
    7276:	48 83 c4 08          	add    $0x8,%rsp
    727a:	5b                   	pop    %rbx
    727b:	5d                   	pop    %rbp
    727c:	c3                   	retq   
    727d:	0f 1f 00             	nopl   (%rax)
				return ZERO_SIZE_PTR;
    7280:	bb 10 00 00 00       	mov    $0x10,%ebx
    7285:	e9 4f ff ff ff       	jmpq   71d9 <l2cap_chan_create+0x39>
    728a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		return NULL;
    7290:	31 c0                	xor    %eax,%eax
    7292:	eb e2                	jmp    7276 <l2cap_chan_create+0xd6>
	BT_DBG("chan %p", chan);
    7294:	48 89 da             	mov    %rbx,%rdx
    7297:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    729e:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    72a5:	31 c0                	xor    %eax,%eax
    72a7:	e8 00 00 00 00       	callq  72ac <l2cap_chan_create+0x10c>
    72ac:	48 89 d8             	mov    %rbx,%rax
    72af:	eb c5                	jmp    7276 <l2cap_chan_create+0xd6>
    72b1:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    72b6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    72bd:	00 00 00 

00000000000072c0 <l2cap_chan_destroy>:
{
    72c0:	55                   	push   %rbp
    72c1:	48 89 e5             	mov    %rsp,%rbp
    72c4:	53                   	push   %rbx
    72c5:	48 83 ec 08          	sub    $0x8,%rsp
    72c9:	e8 00 00 00 00       	callq  72ce <l2cap_chan_destroy+0xe>
    72ce:	48 89 fb             	mov    %rdi,%rbx
	write_lock(&chan_list_lock);
    72d1:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    72d8:	e8 00 00 00 00       	callq  72dd <l2cap_chan_destroy+0x1d>
	list_del(&chan->global_l);
    72dd:	48 8d bb 28 03 00 00 	lea    0x328(%rbx),%rdi
    72e4:	e8 00 00 00 00       	callq  72e9 <l2cap_chan_destroy+0x29>
    72e9:	f0 81 05 00 00 00 00 	lock addl $0x100000,0x0(%rip)        # 72f4 <l2cap_chan_destroy+0x34>
    72f0:	00 00 10 00 
	asm volatile(LOCK_PREFIX "decl %0; sete %1"
    72f4:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    72f8:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    72fb:	84 c0                	test   %al,%al
    72fd:	74 08                	je     7307 <l2cap_chan_destroy+0x47>
		kfree(c);
    72ff:	48 89 df             	mov    %rbx,%rdi
    7302:	e8 00 00 00 00       	callq  7307 <l2cap_chan_destroy+0x47>
}
    7307:	48 83 c4 08          	add    $0x8,%rsp
    730b:	5b                   	pop    %rbx
    730c:	5d                   	pop    %rbp
    730d:	c3                   	retq   
    730e:	66 90                	xchg   %ax,%ax

0000000000007310 <l2cap_chan_set_defaults>:
{
    7310:	55                   	push   %rbp
    7311:	48 89 e5             	mov    %rsp,%rbp
    7314:	e8 00 00 00 00       	callq  7319 <l2cap_chan_set_defaults+0x9>
	chan->tx_win = L2CAP_DEFAULT_TX_WINDOW;
    7319:	b8 3f 00 00 00       	mov    $0x3f,%eax
	chan->tx_win_max = L2CAP_DEFAULT_TX_WINDOW;
    731e:	ba 3f 00 00 00       	mov    $0x3f,%edx
	chan->fcs  = L2CAP_FCS_CRC16;
    7323:	c6 47 6f 01          	movb   $0x1,0x6f(%rdi)
	chan->max_tx = L2CAP_DEFAULT_MAX_TX;
    7327:	c6 47 74 03          	movb   $0x3,0x74(%rdi)
	chan->tx_win = L2CAP_DEFAULT_TX_WINDOW;
    732b:	66 89 47 70          	mov    %ax,0x70(%rdi)
	chan->tx_win_max = L2CAP_DEFAULT_TX_WINDOW;
    732f:	66 89 57 72          	mov    %dx,0x72(%rdi)
	chan->sec_level = BT_SECURITY_LOW;
    7333:	c6 47 2a 01          	movb   $0x1,0x2a(%rdi)
		asm volatile(LOCK_PREFIX "orb %1,%0"
    7337:	f0 80 8f 90 00 00 00 	lock orb $0x2,0x90(%rdi)
    733e:	02 
}
    733f:	5d                   	pop    %rbp
    7340:	c3                   	retq   
    7341:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    7346:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    734d:	00 00 00 

0000000000007350 <l2cap_chan_close>:
{
    7350:	55                   	push   %rbp
    7351:	48 89 e5             	mov    %rsp,%rbp
    7354:	41 57                	push   %r15
    7356:	41 56                	push   %r14
    7358:	41 55                	push   %r13
    735a:	41 54                	push   %r12
    735c:	53                   	push   %rbx
    735d:	48 83 ec 18          	sub    $0x18,%rsp
    7361:	e8 00 00 00 00       	callq  7366 <l2cap_chan_close+0x16>
	BT_DBG("chan %p state %s sk %p", chan,
    7366:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 736d <l2cap_chan_close+0x1d>
	struct l2cap_conn *conn = chan->conn;
    736d:	4c 8b 7f 08          	mov    0x8(%rdi),%r15
{
    7371:	49 89 fd             	mov    %rdi,%r13
    7374:	89 f3                	mov    %esi,%ebx
	struct sock *sk = chan->sk;
    7376:	4c 8b 37             	mov    (%rdi),%r14
	BT_DBG("chan %p state %s sk %p", chan,
    7379:	0f 85 28 02 00 00    	jne    75a7 <l2cap_chan_close+0x257>
	switch (chan->state) {
    737f:	41 0f b6 45 10       	movzbl 0x10(%r13),%eax
    7384:	3c 08                	cmp    $0x8,%al
    7386:	0f 87 b4 01 00 00    	ja     7540 <l2cap_chan_close+0x1f0>
    738c:	0f b6 c8             	movzbl %al,%ecx
    738f:	ff 24 cd 00 00 00 00 	jmpq   *0x0(,%rcx,8)
    7396:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    739d:	00 00 00 
		if (chan->chan_type == L2CAP_CHAN_CONN_ORIENTED &&
    73a0:	41 80 7d 25 03       	cmpb   $0x3,0x25(%r13)
    73a5:	75 69                	jne    7410 <l2cap_chan_close+0xc0>
					conn->hcon->type == ACL_LINK) {
    73a7:	49 8b 07             	mov    (%r15),%rax
		if (chan->chan_type == L2CAP_CHAN_CONN_ORIENTED &&
    73aa:	80 78 21 01          	cmpb   $0x1,0x21(%rax)
    73ae:	75 60                	jne    7410 <l2cap_chan_close+0xc0>
		(addr[nr / BITS_PER_LONG])) != 0;
    73b0:	49 8b 86 b0 02 00 00 	mov    0x2b0(%r14),%rax
			l2cap_state_change(chan, BT_DISCONN);
    73b7:	be 08 00 00 00       	mov    $0x8,%esi
    73bc:	4c 89 ef             	mov    %r13,%rdi
    73bf:	83 e0 01             	and    $0x1,%eax
				result = L2CAP_CR_SEC_BLOCK;
    73c2:	48 83 f8 01          	cmp    $0x1,%rax
    73c6:	45 19 e4             	sbb    %r12d,%r12d
			l2cap_state_change(chan, BT_DISCONN);
    73c9:	e8 52 93 ff ff       	callq  720 <l2cap_state_change>
			rsp.scid   = cpu_to_le16(chan->dcid);
    73ce:	41 0f b7 45 1a       	movzwl 0x1a(%r13),%eax
			l2cap_send_cmd(conn, chan->ident, L2CAP_CONN_RSP,
    73d3:	41 0f b6 75 2b       	movzbl 0x2b(%r13),%esi
    73d8:	4c 8d 45 c8          	lea    -0x38(%rbp),%r8
				result = L2CAP_CR_SEC_BLOCK;
    73dc:	41 83 c4 03          	add    $0x3,%r12d
			l2cap_send_cmd(conn, chan->ident, L2CAP_CONN_RSP,
    73e0:	b9 08 00 00 00       	mov    $0x8,%ecx
    73e5:	ba 03 00 00 00       	mov    $0x3,%edx
    73ea:	4c 89 ff             	mov    %r15,%rdi
			rsp.result = cpu_to_le16(result);
    73ed:	66 44 89 65 cc       	mov    %r12w,-0x34(%rbp)
			rsp.scid   = cpu_to_le16(chan->dcid);
    73f2:	66 89 45 ca          	mov    %ax,-0x36(%rbp)
			rsp.dcid   = cpu_to_le16(chan->scid);
    73f6:	41 0f b7 45 1c       	movzwl 0x1c(%r13),%eax
    73fb:	66 89 45 c8          	mov    %ax,-0x38(%rbp)
			rsp.status = cpu_to_le16(L2CAP_CS_NO_INFO);
    73ff:	31 c0                	xor    %eax,%eax
    7401:	66 89 45 ce          	mov    %ax,-0x32(%rbp)
			l2cap_send_cmd(conn, chan->ident, L2CAP_CONN_RSP,
    7405:	e8 b6 9f ff ff       	callq  13c0 <l2cap_send_cmd>
    740a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		l2cap_chan_del(chan, reason);
    7410:	89 de                	mov    %ebx,%esi
    7412:	4c 89 ef             	mov    %r13,%rdi
    7415:	e8 26 f5 ff ff       	callq  6940 <l2cap_chan_del>
}
    741a:	48 83 c4 18          	add    $0x18,%rsp
    741e:	5b                   	pop    %rbx
    741f:	41 5c                	pop    %r12
    7421:	41 5d                	pop    %r13
    7423:	41 5e                	pop    %r14
    7425:	41 5f                	pop    %r15
    7427:	5d                   	pop    %rbp
    7428:	c3                   	retq   
    7429:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    7430:	31 f6                	xor    %esi,%esi
    7432:	4c 89 f7             	mov    %r14,%rdi
    7435:	e8 00 00 00 00       	callq  743a <l2cap_chan_close+0xea>
	BT_DBG("parent %p", parent);
    743a:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 7441 <l2cap_chan_close+0xf1>
    7441:	74 33                	je     7476 <l2cap_chan_close+0x126>
    7443:	e9 c5 01 00 00       	jmpq   760d <l2cap_chan_close+0x2bd>
    7448:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    744f:	00 
		l2cap_chan_close(chan, ECONNRESET);
    7450:	be 68 00 00 00       	mov    $0x68,%esi
    7455:	48 89 df             	mov    %rbx,%rdi
    7458:	e8 00 00 00 00       	callq  745d <l2cap_chan_close+0x10d>
	mutex_unlock(&chan->lock);
    745d:	4c 89 e7             	mov    %r12,%rdi
    7460:	e8 00 00 00 00       	callq  7465 <l2cap_chan_close+0x115>
		chan->ops->close(chan->data);
    7465:	48 8b 83 40 03 00 00 	mov    0x340(%rbx),%rax
    746c:	48 8b bb 38 03 00 00 	mov    0x338(%rbx),%rdi
    7473:	ff 50 18             	callq  *0x18(%rax)
	while ((sk = bt_accept_dequeue(parent, NULL))) {
    7476:	31 f6                	xor    %esi,%esi
    7478:	4c 89 f7             	mov    %r14,%rdi
    747b:	e8 00 00 00 00       	callq  7480 <l2cap_chan_close+0x130>
    7480:	48 85 c0             	test   %rax,%rax
    7483:	0f 84 e7 00 00 00    	je     7570 <l2cap_chan_close+0x220>
		struct l2cap_chan *chan = l2cap_pi(sk)->chan;
    7489:	48 8b 98 b8 02 00 00 	mov    0x2b8(%rax),%rbx
	mutex_lock(&chan->lock);
    7490:	4c 8d a3 48 03 00 00 	lea    0x348(%rbx),%r12
    7497:	4c 89 e7             	mov    %r12,%rdi
    749a:	e8 00 00 00 00       	callq  749f <l2cap_chan_close+0x14f>
	ret = del_timer_sync(&work->timer);
    749f:	48 8d bb 10 01 00 00 	lea    0x110(%rbx),%rdi
    74a6:	e8 00 00 00 00       	callq  74ab <l2cap_chan_close+0x15b>
	if (ret)
    74ab:	85 c0                	test   %eax,%eax
    74ad:	74 a1                	je     7450 <l2cap_chan_close+0x100>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    74af:	f0 80 a3 f0 00 00 00 	lock andb $0xfe,0xf0(%rbx)
    74b6:	fe 
    74b7:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    74bb:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    74be:	84 c0                	test   %al,%al
    74c0:	74 8e                	je     7450 <l2cap_chan_close+0x100>
		kfree(c);
    74c2:	48 89 df             	mov    %rbx,%rdi
    74c5:	e8 00 00 00 00       	callq  74ca <l2cap_chan_close+0x17a>
    74ca:	eb 84                	jmp    7450 <l2cap_chan_close+0x100>
    74cc:	0f 1f 40 00          	nopl   0x0(%rax)
		if (chan->chan_type == L2CAP_CHAN_CONN_ORIENTED &&
    74d0:	41 80 7d 25 03       	cmpb   $0x3,0x25(%r13)
    74d5:	0f 85 35 ff ff ff    	jne    7410 <l2cap_chan_close+0xc0>
					conn->hcon->type == ACL_LINK) {
    74db:	49 8b 17             	mov    (%r15),%rdx
		if (chan->chan_type == L2CAP_CHAN_CONN_ORIENTED &&
    74de:	80 7a 21 01          	cmpb   $0x1,0x21(%rdx)
    74e2:	0f 85 28 ff ff ff    	jne    7410 <l2cap_chan_close+0xc0>
	BT_DBG("chan %p state %s timeout %ld", chan,
    74e8:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 74ef <l2cap_chan_close+0x19f>
			__set_chan_timer(chan, sk->sk_sndtimeo);
    74ef:	4d 8b a6 a8 01 00 00 	mov    0x1a8(%r14),%r12
    74f6:	4d 8d b5 f0 00 00 00 	lea    0xf0(%r13),%r14
    74fd:	0f 85 df 00 00 00    	jne    75e2 <l2cap_chan_close+0x292>
	ret = del_timer_sync(&work->timer);
    7503:	49 8d bd 10 01 00 00 	lea    0x110(%r13),%rdi
    750a:	e8 00 00 00 00       	callq  750f <l2cap_chan_close+0x1bf>
	if (ret)
    750f:	85 c0                	test   %eax,%eax
    7511:	0f 84 86 00 00 00    	je     759d <l2cap_chan_close+0x24d>
    7517:	f0 41 80 a5 f0 00 00 	lock andb $0xfe,0xf0(%r13)
    751e:	00 fe 
	schedule_delayed_work(work, timeout);
    7520:	4c 89 e6             	mov    %r12,%rsi
    7523:	4c 89 f7             	mov    %r14,%rdi
    7526:	e8 00 00 00 00       	callq  752b <l2cap_chan_close+0x1db>
			l2cap_send_disconn_req(conn, chan, reason);
    752b:	89 da                	mov    %ebx,%edx
    752d:	4c 89 ee             	mov    %r13,%rsi
    7530:	4c 89 ff             	mov    %r15,%rdi
    7533:	e8 c8 b0 ff ff       	callq  2600 <l2cap_send_disconn_req>
    7538:	e9 dd fe ff ff       	jmpq   741a <l2cap_chan_close+0xca>
    753d:	0f 1f 00             	nopl   (%rax)
    7540:	31 f6                	xor    %esi,%esi
    7542:	4c 89 f7             	mov    %r14,%rdi
    7545:	e8 00 00 00 00       	callq  754a <l2cap_chan_close+0x1fa>
	asm volatile("bts %1,%0" : ADDR : "Ir" (nr) : "memory");
    754a:	41 0f ba ae e8 00 00 	btsl   $0x8,0xe8(%r14)
    7551:	00 08 
		release_sock(sk);
    7553:	4c 89 f7             	mov    %r14,%rdi
    7556:	e8 00 00 00 00       	callq  755b <l2cap_chan_close+0x20b>
}
    755b:	48 83 c4 18          	add    $0x18,%rsp
    755f:	5b                   	pop    %rbx
    7560:	41 5c                	pop    %r12
    7562:	41 5d                	pop    %r13
    7564:	41 5e                	pop    %r14
    7566:	41 5f                	pop    %r15
    7568:	5d                   	pop    %rbp
    7569:	c3                   	retq   
    756a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		__l2cap_state_change(chan, BT_CLOSED);
    7570:	be 09 00 00 00       	mov    $0x9,%esi
    7575:	4c 89 ef             	mov    %r13,%rdi
    7578:	e8 13 8b ff ff       	callq  90 <__l2cap_state_change>
    757d:	41 0f ba ae e8 00 00 	btsl   $0x8,0xe8(%r14)
    7584:	00 08 
		release_sock(sk);
    7586:	4c 89 f7             	mov    %r14,%rdi
    7589:	e8 00 00 00 00       	callq  758e <l2cap_chan_close+0x23e>
}
    758e:	48 83 c4 18          	add    $0x18,%rsp
    7592:	5b                   	pop    %rbx
    7593:	41 5c                	pop    %r12
    7595:	41 5d                	pop    %r13
    7597:	41 5e                	pop    %r14
    7599:	41 5f                	pop    %r15
    759b:	5d                   	pop    %rbp
    759c:	c3                   	retq   
	asm volatile(LOCK_PREFIX "incl %0"
    759d:	f0 41 ff 45 14       	lock incl 0x14(%r13)
    75a2:	e9 79 ff ff ff       	jmpq   7520 <l2cap_chan_close+0x1d0>
    75a7:	0f b6 47 10          	movzbl 0x10(%rdi),%eax
    75ab:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    75b2:	83 e8 01             	sub    $0x1,%eax
    75b5:	83 f8 08             	cmp    $0x8,%eax
    75b8:	77 08                	ja     75c2 <l2cap_chan_close+0x272>
    75ba:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    75c1:	00 
	BT_DBG("chan %p state %s sk %p", chan,
    75c2:	4d 89 f0             	mov    %r14,%r8
    75c5:	4c 89 ea             	mov    %r13,%rdx
    75c8:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    75cf:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    75d6:	31 c0                	xor    %eax,%eax
    75d8:	e8 00 00 00 00       	callq  75dd <l2cap_chan_close+0x28d>
    75dd:	e9 9d fd ff ff       	jmpq   737f <l2cap_chan_close+0x2f>
    75e2:	83 e8 01             	sub    $0x1,%eax
	BT_DBG("chan %p state %s timeout %ld", chan,
    75e5:	4d 89 e0             	mov    %r12,%r8
    75e8:	4c 89 ea             	mov    %r13,%rdx
    75eb:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    75f2:	00 
    75f3:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    75fa:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    7601:	31 c0                	xor    %eax,%eax
    7603:	e8 00 00 00 00       	callq  7608 <l2cap_chan_close+0x2b8>
    7608:	e9 f6 fe ff ff       	jmpq   7503 <l2cap_chan_close+0x1b3>
	BT_DBG("parent %p", parent);
    760d:	4c 89 f2             	mov    %r14,%rdx
    7610:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    7617:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    761e:	31 c0                	xor    %eax,%eax
    7620:	e8 00 00 00 00       	callq  7625 <l2cap_chan_close+0x2d5>
    7625:	e9 4c fe ff ff       	jmpq   7476 <l2cap_chan_close+0x126>
    762a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000007630 <l2cap_chan_timeout>:
{
    7630:	55                   	push   %rbp
    7631:	48 89 e5             	mov    %rsp,%rbp
    7634:	41 56                	push   %r14
    7636:	41 55                	push   %r13
    7638:	41 54                	push   %r12
    763a:	53                   	push   %rbx
    763b:	e8 00 00 00 00       	callq  7640 <l2cap_chan_timeout+0x10>
	BT_DBG("chan %p state %s", chan, state_to_string(chan->state));
    7640:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 7647 <l2cap_chan_timeout+0x17>
	struct l2cap_conn *conn = chan->conn;
    7647:	4c 8b a7 18 ff ff ff 	mov    -0xe8(%rdi),%r12
{
    764e:	48 89 fb             	mov    %rdi,%rbx
	struct l2cap_chan *chan = container_of(work, struct l2cap_chan,
    7651:	4c 8d b7 10 ff ff ff 	lea    -0xf0(%rdi),%r14
	BT_DBG("chan %p state %s", chan, state_to_string(chan->state));
    7658:	0f 85 a0 00 00 00    	jne    76fe <l2cap_chan_timeout+0xce>
	mutex_lock(&conn->chan_lock);
    765e:	49 81 c4 40 01 00 00 	add    $0x140,%r12
	mutex_lock(&chan->lock);
    7665:	4c 8d ab 58 02 00 00 	lea    0x258(%rbx),%r13
    766c:	4c 89 e7             	mov    %r12,%rdi
    766f:	e8 00 00 00 00       	callq  7674 <l2cap_chan_timeout+0x44>
    7674:	4c 89 ef             	mov    %r13,%rdi
    7677:	e8 00 00 00 00       	callq  767c <l2cap_chan_timeout+0x4c>
	if (chan->state == BT_CONNECTED || chan->state == BT_CONFIG)
    767c:	0f b6 83 20 ff ff ff 	movzbl -0xe0(%rbx),%eax
    7683:	3c 07                	cmp    $0x7,%al
    7685:	74 59                	je     76e0 <l2cap_chan_timeout+0xb0>
    7687:	3c 01                	cmp    $0x1,%al
    7689:	74 55                	je     76e0 <l2cap_chan_timeout+0xb0>
	else if (chan->state == BT_CONNECT &&
    768b:	3c 05                	cmp    $0x5,%al
		reason = ETIMEDOUT;
    768d:	be 6e 00 00 00       	mov    $0x6e,%esi
	else if (chan->state == BT_CONNECT &&
    7692:	74 5c                	je     76f0 <l2cap_chan_timeout+0xc0>
	l2cap_chan_close(chan, reason);
    7694:	4c 89 f7             	mov    %r14,%rdi
    7697:	e8 00 00 00 00       	callq  769c <l2cap_chan_timeout+0x6c>
	mutex_unlock(&chan->lock);
    769c:	4c 89 ef             	mov    %r13,%rdi
    769f:	e8 00 00 00 00       	callq  76a4 <l2cap_chan_timeout+0x74>
	chan->ops->close(chan->data);
    76a4:	48 8b 83 50 02 00 00 	mov    0x250(%rbx),%rax
    76ab:	48 8b bb 48 02 00 00 	mov    0x248(%rbx),%rdi
    76b2:	ff 50 18             	callq  *0x18(%rax)
	mutex_unlock(&conn->chan_lock);
    76b5:	4c 89 e7             	mov    %r12,%rdi
    76b8:	e8 00 00 00 00       	callq  76bd <l2cap_chan_timeout+0x8d>
	asm volatile(LOCK_PREFIX "decl %0; sete %1"
    76bd:	f0 ff 8b 24 ff ff ff 	lock decl -0xdc(%rbx)
    76c4:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    76c7:	84 c0                	test   %al,%al
    76c9:	74 08                	je     76d3 <l2cap_chan_timeout+0xa3>
		kfree(c);
    76cb:	4c 89 f7             	mov    %r14,%rdi
    76ce:	e8 00 00 00 00       	callq  76d3 <l2cap_chan_timeout+0xa3>
}
    76d3:	5b                   	pop    %rbx
    76d4:	41 5c                	pop    %r12
    76d6:	41 5d                	pop    %r13
    76d8:	41 5e                	pop    %r14
    76da:	5d                   	pop    %rbp
    76db:	c3                   	retq   
    76dc:	0f 1f 40 00          	nopl   0x0(%rax)
		reason = ECONNREFUSED;
    76e0:	be 6f 00 00 00       	mov    $0x6f,%esi
    76e5:	eb ad                	jmp    7694 <l2cap_chan_timeout+0x64>
    76e7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    76ee:	00 00 
		reason = ETIMEDOUT;
    76f0:	80 bb 3a ff ff ff 01 	cmpb   $0x1,-0xc6(%rbx)
    76f7:	19 f6                	sbb    %esi,%esi
    76f9:	83 c6 6f             	add    $0x6f,%esi
    76fc:	eb 96                	jmp    7694 <l2cap_chan_timeout+0x64>
    76fe:	0f b6 87 20 ff ff ff 	movzbl -0xe0(%rdi),%eax
    7705:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    770c:	83 e8 01             	sub    $0x1,%eax
    770f:	83 f8 08             	cmp    $0x8,%eax
    7712:	77 08                	ja     771c <l2cap_chan_timeout+0xec>
    7714:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    771b:	00 
	BT_DBG("chan %p state %s", chan, state_to_string(chan->state));
    771c:	4c 89 f2             	mov    %r14,%rdx
    771f:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    7726:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    772d:	31 c0                	xor    %eax,%eax
    772f:	e8 00 00 00 00       	callq  7734 <l2cap_chan_timeout+0x104>
    7734:	e9 25 ff ff ff       	jmpq   765e <l2cap_chan_timeout+0x2e>
    7739:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000007740 <l2cap_chan_check_security>:
{
    7740:	55                   	push   %rbp
    7741:	48 89 e5             	mov    %rsp,%rbp
    7744:	e8 00 00 00 00       	callq  7749 <l2cap_chan_check_security+0x9>
	if (chan->chan_type == L2CAP_CHAN_RAW) {
    7749:	80 7f 25 01          	cmpb   $0x1,0x25(%rdi)
	struct l2cap_conn *conn = chan->conn;
    774d:	48 8b 47 08          	mov    0x8(%rdi),%rax
int l2cap_chan_check_security(struct l2cap_chan *chan)
    7751:	0f b7 57 18          	movzwl 0x18(%rdi),%edx
		switch (chan->sec_level) {
    7755:	0f b6 77 2a          	movzbl 0x2a(%rdi),%esi
	if (chan->chan_type == L2CAP_CHAN_RAW) {
    7759:	74 25                	je     7780 <l2cap_chan_check_security+0x40>
	} else if (chan->psm == cpu_to_le16(0x0001)) {
    775b:	66 83 fa 01          	cmp    $0x1,%dx
    775f:	74 3f                	je     77a0 <l2cap_chan_check_security+0x60>
		switch (chan->sec_level) {
    7761:	40 80 fe 02          	cmp    $0x2,%sil
    7765:	74 59                	je     77c0 <l2cap_chan_check_security+0x80>
    7767:	40 80 fe 03          	cmp    $0x3,%sil
    776b:	74 6b                	je     77d8 <l2cap_chan_check_security+0x98>
			chan->sec_level = BT_SECURITY_SDP;
    776d:	31 d2                	xor    %edx,%edx
	return hci_conn_security(conn->hcon, chan->sec_level, auth_type);
    776f:	48 8b 38             	mov    (%rax),%rdi
    7772:	e8 00 00 00 00       	callq  7777 <l2cap_chan_check_security+0x37>
}
    7777:	5d                   	pop    %rbp
    7778:	c3                   	retq   
    7779:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		switch (chan->sec_level) {
    7780:	40 80 fe 02          	cmp    $0x2,%sil
    7784:	74 6a                	je     77f0 <l2cap_chan_check_security+0xb0>
    7786:	40 80 fe 03          	cmp    $0x3,%sil
    778a:	75 e1                	jne    776d <l2cap_chan_check_security+0x2d>
    778c:	be 03 00 00 00       	mov    $0x3,%esi
    7791:	ba 03 00 00 00       	mov    $0x3,%edx
    7796:	eb d7                	jmp    776f <l2cap_chan_check_security+0x2f>
    7798:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    779f:	00 
		if (chan->sec_level == BT_SECURITY_LOW)
    77a0:	40 80 fe 01          	cmp    $0x1,%sil
    77a4:	74 5a                	je     7800 <l2cap_chan_check_security+0xc0>
	return hci_conn_security(conn->hcon, chan->sec_level, auth_type);
    77a6:	48 8b 38             	mov    (%rax),%rdi
    77a9:	31 d2                	xor    %edx,%edx
    77ab:	40 80 fe 03          	cmp    $0x3,%sil
    77af:	0f 94 c2             	sete   %dl
    77b2:	e8 00 00 00 00       	callq  77b7 <l2cap_chan_check_security+0x77>
}
    77b7:	5d                   	pop    %rbp
    77b8:	c3                   	retq   
    77b9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
	return hci_conn_security(conn->hcon, chan->sec_level, auth_type);
    77c0:	48 8b 38             	mov    (%rax),%rdi
    77c3:	be 02 00 00 00       	mov    $0x2,%esi
    77c8:	ba 04 00 00 00       	mov    $0x4,%edx
    77cd:	e8 00 00 00 00       	callq  77d2 <l2cap_chan_check_security+0x92>
}
    77d2:	5d                   	pop    %rbp
    77d3:	c3                   	retq   
    77d4:	0f 1f 40 00          	nopl   0x0(%rax)
	return hci_conn_security(conn->hcon, chan->sec_level, auth_type);
    77d8:	48 8b 38             	mov    (%rax),%rdi
		switch (chan->sec_level) {
    77db:	be 03 00 00 00       	mov    $0x3,%esi
    77e0:	ba 05 00 00 00       	mov    $0x5,%edx
	return hci_conn_security(conn->hcon, chan->sec_level, auth_type);
    77e5:	e8 00 00 00 00       	callq  77ea <l2cap_chan_check_security+0xaa>
}
    77ea:	5d                   	pop    %rbp
    77eb:	c3                   	retq   
    77ec:	0f 1f 40 00          	nopl   0x0(%rax)
    77f0:	be 02 00 00 00       	mov    $0x2,%esi
    77f5:	ba 02 00 00 00       	mov    $0x2,%edx
    77fa:	e9 70 ff ff ff       	jmpq   776f <l2cap_chan_check_security+0x2f>
    77ff:	90                   	nop
			chan->sec_level = BT_SECURITY_SDP;
    7800:	c6 47 2a 00          	movb   $0x0,0x2a(%rdi)
    7804:	31 f6                	xor    %esi,%esi
    7806:	e9 62 ff ff ff       	jmpq   776d <l2cap_chan_check_security+0x2d>
    780b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000007810 <l2cap_conn_start>:
{
    7810:	55                   	push   %rbp
    7811:	48 89 e5             	mov    %rsp,%rbp
    7814:	41 57                	push   %r15
    7816:	41 56                	push   %r14
    7818:	41 55                	push   %r13
    781a:	41 54                	push   %r12
    781c:	53                   	push   %rbx
    781d:	48 81 ec a8 00 00 00 	sub    $0xa8,%rsp
    7824:	e8 00 00 00 00       	callq  7829 <l2cap_conn_start+0x19>
    7829:	65 48 8b 04 25 28 00 	mov    %gs:0x28,%rax
    7830:	00 00 
    7832:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    7836:	31 c0                	xor    %eax,%eax
	BT_DBG("conn %p", conn);
    7838:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 783f <l2cap_conn_start+0x2f>
{
    783f:	48 89 bd 38 ff ff ff 	mov    %rdi,-0xc8(%rbp)
	BT_DBG("conn %p", conn);
    7846:	0f 85 b1 02 00 00    	jne    7afd <l2cap_conn_start+0x2ed>
	mutex_lock(&conn->chan_lock);
    784c:	48 8b 9d 38 ff ff ff 	mov    -0xc8(%rbp),%rbx
    7853:	48 89 d8             	mov    %rbx,%rax
	list_for_each_entry_safe(chan, tmp, &conn->chan_l, list) {
    7856:	4c 8d a3 30 01 00 00 	lea    0x130(%rbx),%r12
	mutex_lock(&conn->chan_lock);
    785d:	48 05 40 01 00 00    	add    $0x140,%rax
    7863:	48 89 c7             	mov    %rax,%rdi
    7866:	48 89 85 30 ff ff ff 	mov    %rax,-0xd0(%rbp)
    786d:	e8 00 00 00 00       	callq  7872 <l2cap_conn_start+0x62>
	list_for_each_entry_safe(chan, tmp, &conn->chan_l, list) {
    7872:	48 8b 83 30 01 00 00 	mov    0x130(%rbx),%rax
    7879:	48 8b 30             	mov    (%rax),%rsi
    787c:	49 39 c4             	cmp    %rax,%r12
    787f:	4c 8d b0 e8 fc ff ff 	lea    -0x318(%rax),%r14
    7886:	4c 8d be e8 fc ff ff 	lea    -0x318(%rsi),%r15
    788d:	75 0f                	jne    789e <l2cap_conn_start+0x8e>
    788f:	eb 59                	jmp    78ea <l2cap_conn_start+0xda>
    7891:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    7898:	4d 89 fe             	mov    %r15,%r14
    789b:	49 89 d7             	mov    %rdx,%r15
	mutex_lock(&chan->lock);
    789e:	49 8d 9e 48 03 00 00 	lea    0x348(%r14),%rbx
		struct sock *sk = chan->sk;
    78a5:	4d 8b 2e             	mov    (%r14),%r13
    78a8:	48 89 df             	mov    %rbx,%rdi
    78ab:	e8 00 00 00 00       	callq  78b0 <l2cap_conn_start+0xa0>
		if (chan->chan_type != L2CAP_CHAN_CONN_ORIENTED) {
    78b0:	41 80 7e 25 03       	cmpb   $0x3,0x25(%r14)
    78b5:	75 11                	jne    78c8 <l2cap_conn_start+0xb8>
		if (chan->state == BT_CONNECT) {
    78b7:	41 0f b6 46 10       	movzbl 0x10(%r14),%eax
    78bc:	3c 05                	cmp    $0x5,%al
    78be:	74 60                	je     7920 <l2cap_conn_start+0x110>
		} else if (chan->state == BT_CONNECT2) {
    78c0:	3c 06                	cmp    $0x6,%al
    78c2:	0f 84 c8 00 00 00    	je     7990 <l2cap_conn_start+0x180>
	mutex_unlock(&chan->lock);
    78c8:	48 89 df             	mov    %rbx,%rdi
    78cb:	e8 00 00 00 00       	callq  78d0 <l2cap_conn_start+0xc0>
	list_for_each_entry_safe(chan, tmp, &conn->chan_l, list) {
    78d0:	49 8b 87 18 03 00 00 	mov    0x318(%r15),%rax
    78d7:	48 8d 90 e8 fc ff ff 	lea    -0x318(%rax),%rdx
    78de:	49 8d 87 18 03 00 00 	lea    0x318(%r15),%rax
    78e5:	49 39 c4             	cmp    %rax,%r12
    78e8:	75 ae                	jne    7898 <l2cap_conn_start+0x88>
	mutex_unlock(&conn->chan_lock);
    78ea:	48 8b bd 30 ff ff ff 	mov    -0xd0(%rbp),%rdi
    78f1:	e8 00 00 00 00       	callq  78f6 <l2cap_conn_start+0xe6>
}
    78f6:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    78fa:	65 48 33 04 25 28 00 	xor    %gs:0x28,%rax
    7901:	00 00 
    7903:	0f 85 ef 01 00 00    	jne    7af8 <l2cap_conn_start+0x2e8>
    7909:	48 81 c4 a8 00 00 00 	add    $0xa8,%rsp
    7910:	5b                   	pop    %rbx
    7911:	41 5c                	pop    %r12
    7913:	41 5d                	pop    %r13
    7915:	41 5e                	pop    %r14
    7917:	41 5f                	pop    %r15
    7919:	5d                   	pop    %rbp
    791a:	c3                   	retq   
    791b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
			if (!l2cap_chan_check_security(chan) ||
    7920:	4c 89 f7             	mov    %r14,%rdi
    7923:	e8 00 00 00 00       	callq  7928 <l2cap_conn_start+0x118>
    7928:	85 c0                	test   %eax,%eax
    792a:	74 9c                	je     78c8 <l2cap_conn_start+0xb8>
		(addr[nr / BITS_PER_LONG])) != 0;
    792c:	49 8b 86 80 00 00 00 	mov    0x80(%r14),%rax
    7933:	a8 20                	test   $0x20,%al
    7935:	75 91                	jne    78c8 <l2cap_conn_start+0xb8>
	u32 local_feat_mask = l2cap_feat_mask;
    7937:	80 3d 00 00 00 00 01 	cmpb   $0x1,0x0(%rip)        # 793e <l2cap_conn_start+0x12e>
			if (!l2cap_mode_supported(chan->mode, conn->feat_mask)
    793e:	48 8b 85 38 ff ff ff 	mov    -0xc8(%rbp),%rax
    7945:	41 0f b6 56 24       	movzbl 0x24(%r14),%edx
    794a:	8b 48 24             	mov    0x24(%rax),%ecx
	u32 local_feat_mask = l2cap_feat_mask;
    794d:	19 c0                	sbb    %eax,%eax
    794f:	83 e0 18             	and    $0x18,%eax
    7952:	83 e8 80             	sub    $0xffffff80,%eax
	switch (mode) {
    7955:	80 fa 03             	cmp    $0x3,%dl
    7958:	0f 84 55 01 00 00    	je     7ab3 <l2cap_conn_start+0x2a3>
    795e:	80 fa 04             	cmp    $0x4,%dl
    7961:	75 09                	jne    796c <l2cap_conn_start+0x15c>
		return L2CAP_FEAT_STREAMING & feat_mask & local_feat_mask;
    7963:	21 c8                	and    %ecx,%eax
    7965:	83 e0 10             	and    $0x10,%eax
			if (!l2cap_mode_supported(chan->mode, conn->feat_mask)
    7968:	85 c0                	test   %eax,%eax
    796a:	75 0f                	jne    797b <l2cap_conn_start+0x16b>
    796c:	49 8b 86 80 00 00 00 	mov    0x80(%r14),%rax
					&& test_bit(CONF_STATE2_DEVICE,
    7973:	a8 80                	test   $0x80,%al
    7975:	0f 85 63 01 00 00    	jne    7ade <l2cap_conn_start+0x2ce>
			l2cap_send_conn_req(chan);
    797b:	4c 89 f7             	mov    %r14,%rdi
    797e:	e8 8d 9c ff ff       	callq  1610 <l2cap_send_conn_req>
    7983:	e9 40 ff ff ff       	jmpq   78c8 <l2cap_conn_start+0xb8>
    7988:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    798f:	00 
			rsp.scid = cpu_to_le16(chan->dcid);
    7990:	41 0f b7 46 1a       	movzwl 0x1a(%r14),%eax
			if (l2cap_chan_check_security(chan)) {
    7995:	4c 89 f7             	mov    %r14,%rdi
			rsp.scid = cpu_to_le16(chan->dcid);
    7998:	66 89 85 42 ff ff ff 	mov    %ax,-0xbe(%rbp)
			rsp.dcid = cpu_to_le16(chan->scid);
    799f:	41 0f b7 46 1c       	movzwl 0x1c(%r14),%eax
    79a4:	66 89 85 40 ff ff ff 	mov    %ax,-0xc0(%rbp)
			if (l2cap_chan_check_security(chan)) {
    79ab:	e8 00 00 00 00       	callq  79b0 <l2cap_conn_start+0x1a0>
    79b0:	85 c0                	test   %eax,%eax
    79b2:	0f 85 a8 00 00 00    	jne    7a60 <l2cap_conn_start+0x250>
				rsp.result = cpu_to_le16(L2CAP_CR_PEND);
    79b8:	b8 01 00 00 00       	mov    $0x1,%eax
				rsp.status = cpu_to_le16(L2CAP_CS_AUTHEN_PEND);
    79bd:	ba 01 00 00 00       	mov    $0x1,%edx
				rsp.result = cpu_to_le16(L2CAP_CR_PEND);
    79c2:	66 89 85 44 ff ff ff 	mov    %ax,-0xbc(%rbp)
				rsp.status = cpu_to_le16(L2CAP_CS_AUTHEN_PEND);
    79c9:	66 89 95 46 ff ff ff 	mov    %dx,-0xba(%rbp)
			l2cap_send_cmd(conn, chan->ident, L2CAP_CONN_RSP,
    79d0:	41 0f b6 76 2b       	movzbl 0x2b(%r14),%esi
    79d5:	48 8b bd 38 ff ff ff 	mov    -0xc8(%rbp),%rdi
    79dc:	4c 8d 85 40 ff ff ff 	lea    -0xc0(%rbp),%r8
    79e3:	b9 08 00 00 00       	mov    $0x8,%ecx
    79e8:	ba 03 00 00 00       	mov    $0x3,%edx
    79ed:	e8 ce 99 ff ff       	callq  13c0 <l2cap_send_cmd>
    79f2:	49 8b 86 80 00 00 00 	mov    0x80(%r14),%rax
			if (test_bit(CONF_REQ_SENT, &chan->conf_state) ||
    79f9:	a8 01                	test   $0x1,%al
    79fb:	0f 85 c7 fe ff ff    	jne    78c8 <l2cap_conn_start+0xb8>
    7a01:	66 83 bd 44 ff ff ff 	cmpw   $0x0,-0xbc(%rbp)
    7a08:	00 
    7a09:	0f 85 b9 fe ff ff    	jne    78c8 <l2cap_conn_start+0xb8>
		asm volatile(LOCK_PREFIX "orb %1,%0"
    7a0f:	f0 41 80 8e 80 00 00 	lock orb $0x1,0x80(%r14)
    7a16:	00 01 
						l2cap_build_conf_req(chan, buf), buf);
    7a18:	48 8d b5 48 ff ff ff 	lea    -0xb8(%rbp),%rsi
    7a1f:	4c 89 f7             	mov    %r14,%rdi
    7a22:	e8 49 9c ff ff       	callq  1670 <l2cap_build_conf_req>
			l2cap_send_cmd(conn, l2cap_get_ident(conn), L2CAP_CONF_REQ,
    7a27:	48 8b bd 38 ff ff ff 	mov    -0xc8(%rbp),%rdi
						l2cap_build_conf_req(chan, buf), buf);
    7a2e:	41 89 c5             	mov    %eax,%r13d
			l2cap_send_cmd(conn, l2cap_get_ident(conn), L2CAP_CONF_REQ,
    7a31:	e8 7a 8a ff ff       	callq  4b0 <l2cap_get_ident>
    7a36:	48 8b bd 38 ff ff ff 	mov    -0xc8(%rbp),%rdi
    7a3d:	4c 8d 85 48 ff ff ff 	lea    -0xb8(%rbp),%r8
    7a44:	41 0f b7 cd          	movzwl %r13w,%ecx
    7a48:	0f b6 f0             	movzbl %al,%esi
    7a4b:	ba 04 00 00 00       	mov    $0x4,%edx
    7a50:	e8 6b 99 ff ff       	callq  13c0 <l2cap_send_cmd>
			chan->num_conf_req++;
    7a55:	41 80 46 6d 01       	addb   $0x1,0x6d(%r14)
    7a5a:	e9 69 fe ff ff       	jmpq   78c8 <l2cap_conn_start+0xb8>
    7a5f:	90                   	nop
    7a60:	31 f6                	xor    %esi,%esi
    7a62:	4c 89 ef             	mov    %r13,%rdi
    7a65:	e8 00 00 00 00       	callq  7a6a <l2cap_conn_start+0x25a>
		(addr[nr / BITS_PER_LONG])) != 0;
    7a6a:	49 8b 85 b0 02 00 00 	mov    0x2b0(%r13),%rax
				if (test_bit(BT_SK_DEFER_SETUP,
    7a71:	a8 01                	test   $0x1,%al
    7a73:	74 48                	je     7abd <l2cap_conn_start+0x2ad>
					struct sock *parent = bt_sk(sk)->parent;
    7a75:	49 8b 85 a8 02 00 00 	mov    0x2a8(%r13),%rax
					rsp.result = cpu_to_le16(L2CAP_CR_PEND);
    7a7c:	bf 01 00 00 00       	mov    $0x1,%edi
					rsp.status = cpu_to_le16(L2CAP_CS_AUTHOR_PEND);
    7a81:	41 b8 02 00 00 00    	mov    $0x2,%r8d
					rsp.result = cpu_to_le16(L2CAP_CR_PEND);
    7a87:	66 89 bd 44 ff ff ff 	mov    %di,-0xbc(%rbp)
					rsp.status = cpu_to_le16(L2CAP_CS_AUTHOR_PEND);
    7a8e:	66 44 89 85 46 ff ff 	mov    %r8w,-0xba(%rbp)
    7a95:	ff 
					if (parent)
    7a96:	48 85 c0             	test   %rax,%rax
    7a99:	74 0b                	je     7aa6 <l2cap_conn_start+0x296>
						parent->sk_data_ready(parent, 0);
    7a9b:	31 f6                	xor    %esi,%esi
    7a9d:	48 89 c7             	mov    %rax,%rdi
    7aa0:	ff 90 60 02 00 00    	callq  *0x260(%rax)
				release_sock(sk);
    7aa6:	4c 89 ef             	mov    %r13,%rdi
    7aa9:	e8 00 00 00 00       	callq  7aae <l2cap_conn_start+0x29e>
    7aae:	e9 1d ff ff ff       	jmpq   79d0 <l2cap_conn_start+0x1c0>
		return L2CAP_FEAT_ERTM & feat_mask & local_feat_mask;
    7ab3:	21 c8                	and    %ecx,%eax
    7ab5:	83 e0 08             	and    $0x8,%eax
    7ab8:	e9 ab fe ff ff       	jmpq   7968 <l2cap_conn_start+0x158>
					__l2cap_state_change(chan, BT_CONFIG);
    7abd:	be 07 00 00 00       	mov    $0x7,%esi
    7ac2:	4c 89 f7             	mov    %r14,%rdi
    7ac5:	e8 c6 85 ff ff       	callq  90 <__l2cap_state_change>
					rsp.result = cpu_to_le16(L2CAP_CR_SUCCESS);
    7aca:	31 c9                	xor    %ecx,%ecx
					rsp.status = cpu_to_le16(L2CAP_CS_NO_INFO);
    7acc:	31 f6                	xor    %esi,%esi
					rsp.result = cpu_to_le16(L2CAP_CR_SUCCESS);
    7ace:	66 89 8d 44 ff ff ff 	mov    %cx,-0xbc(%rbp)
					rsp.status = cpu_to_le16(L2CAP_CS_NO_INFO);
    7ad5:	66 89 b5 46 ff ff ff 	mov    %si,-0xba(%rbp)
    7adc:	eb c8                	jmp    7aa6 <l2cap_conn_start+0x296>
				l2cap_chan_close(chan, ECONNRESET);
    7ade:	4c 89 f7             	mov    %r14,%rdi
    7ae1:	be 68 00 00 00       	mov    $0x68,%esi
    7ae6:	e8 00 00 00 00       	callq  7aeb <l2cap_conn_start+0x2db>
    7aeb:	48 89 df             	mov    %rbx,%rdi
    7aee:	e8 00 00 00 00       	callq  7af3 <l2cap_conn_start+0x2e3>
				continue;
    7af3:	e9 d8 fd ff ff       	jmpq   78d0 <l2cap_conn_start+0xc0>
}
    7af8:	e8 00 00 00 00       	callq  7afd <l2cap_conn_start+0x2ed>
	BT_DBG("conn %p", conn);
    7afd:	48 89 fa             	mov    %rdi,%rdx
    7b00:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    7b07:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    7b0e:	e8 00 00 00 00       	callq  7b13 <l2cap_conn_start+0x303>
    7b13:	e9 34 fd ff ff       	jmpq   784c <l2cap_conn_start+0x3c>
    7b18:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    7b1f:	00 

0000000000007b20 <l2cap_info_timeout>:
{
    7b20:	55                   	push   %rbp
    7b21:	48 89 e5             	mov    %rsp,%rbp
    7b24:	e8 00 00 00 00       	callq  7b29 <l2cap_info_timeout+0x9>
	conn->info_state |= L2CAP_INFO_FEAT_MASK_REQ_DONE;
    7b29:	80 4f f9 08          	orb    $0x8,-0x7(%rdi)
	conn->info_ident = 0;
    7b2d:	c6 47 fa 00          	movb   $0x0,-0x6(%rdi)
	struct l2cap_conn *conn = container_of(work, struct l2cap_conn,
    7b31:	48 83 ef 30          	sub    $0x30,%rdi
	l2cap_conn_start(conn);
    7b35:	e8 d6 fc ff ff       	callq  7810 <l2cap_conn_start>
}
    7b3a:	5d                   	pop    %rbp
    7b3b:	c3                   	retq   
    7b3c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000007b40 <l2cap_do_start>:
{
    7b40:	55                   	push   %rbp
    7b41:	48 89 e5             	mov    %rsp,%rbp
    7b44:	41 54                	push   %r12
    7b46:	53                   	push   %rbx
    7b47:	48 83 ec 10          	sub    $0x10,%rsp
    7b4b:	e8 00 00 00 00       	callq  7b50 <l2cap_do_start+0x10>
	struct l2cap_conn *conn = chan->conn;
    7b50:	48 8b 5f 08          	mov    0x8(%rdi),%rbx
{
    7b54:	49 89 fc             	mov    %rdi,%r12
	if (conn->hcon->type == LE_LINK) {
    7b57:	48 8b 03             	mov    (%rbx),%rax
    7b5a:	80 78 21 80          	cmpb   $0x80,0x21(%rax)
    7b5e:	0f 84 94 00 00 00    	je     7bf8 <l2cap_do_start+0xb8>
	if (conn->info_state & L2CAP_INFO_FEAT_MASK_REQ_SENT) {
    7b64:	0f b6 43 29          	movzbl 0x29(%rbx),%eax
    7b68:	a8 04                	test   $0x4,%al
    7b6a:	74 34                	je     7ba0 <l2cap_do_start+0x60>
		if (!(conn->info_state & L2CAP_INFO_FEAT_MASK_REQ_DONE))
    7b6c:	a8 08                	test   $0x8,%al
    7b6e:	75 10                	jne    7b80 <l2cap_do_start+0x40>
}
    7b70:	48 83 c4 10          	add    $0x10,%rsp
    7b74:	5b                   	pop    %rbx
    7b75:	41 5c                	pop    %r12
    7b77:	5d                   	pop    %rbp
    7b78:	c3                   	retq   
    7b79:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		if (l2cap_chan_check_security(chan) &&
    7b80:	e8 00 00 00 00       	callq  7b85 <l2cap_do_start+0x45>
    7b85:	85 c0                	test   %eax,%eax
    7b87:	74 e7                	je     7b70 <l2cap_do_start+0x30>
    7b89:	49 8b 84 24 80 00 00 	mov    0x80(%r12),%rax
    7b90:	00 
    7b91:	a8 20                	test   $0x20,%al
    7b93:	75 db                	jne    7b70 <l2cap_do_start+0x30>
			l2cap_send_conn_req(chan);
    7b95:	4c 89 e7             	mov    %r12,%rdi
    7b98:	e8 73 9a ff ff       	callq  1610 <l2cap_send_conn_req>
    7b9d:	eb d1                	jmp    7b70 <l2cap_do_start+0x30>
    7b9f:	90                   	nop
		conn->info_state |= L2CAP_INFO_FEAT_MASK_REQ_SENT;
    7ba0:	83 c8 04             	or     $0x4,%eax
		req.type = cpu_to_le16(L2CAP_IT_FEAT_MASK);
    7ba3:	ba 02 00 00 00       	mov    $0x2,%edx
		conn->info_ident = l2cap_get_ident(conn);
    7ba8:	48 89 df             	mov    %rbx,%rdi
		conn->info_state |= L2CAP_INFO_FEAT_MASK_REQ_SENT;
    7bab:	88 43 29             	mov    %al,0x29(%rbx)
		req.type = cpu_to_le16(L2CAP_IT_FEAT_MASK);
    7bae:	66 89 55 ee          	mov    %dx,-0x12(%rbp)
		conn->info_ident = l2cap_get_ident(conn);
    7bb2:	e8 f9 88 ff ff       	callq  4b0 <l2cap_get_ident>
		schedule_delayed_work(&conn->info_timer, L2CAP_INFO_TIMEOUT);
    7bb7:	bf a0 0f 00 00       	mov    $0xfa0,%edi
		conn->info_ident = l2cap_get_ident(conn);
    7bbc:	88 43 2a             	mov    %al,0x2a(%rbx)
		schedule_delayed_work(&conn->info_timer, L2CAP_INFO_TIMEOUT);
    7bbf:	e8 00 00 00 00       	callq  7bc4 <l2cap_do_start+0x84>
    7bc4:	48 8d 7b 30          	lea    0x30(%rbx),%rdi
    7bc8:	48 89 c6             	mov    %rax,%rsi
    7bcb:	e8 00 00 00 00       	callq  7bd0 <l2cap_do_start+0x90>
		l2cap_send_cmd(conn, conn->info_ident,
    7bd0:	0f b6 73 2a          	movzbl 0x2a(%rbx),%esi
    7bd4:	4c 8d 45 ee          	lea    -0x12(%rbp),%r8
    7bd8:	48 89 df             	mov    %rbx,%rdi
    7bdb:	b9 02 00 00 00       	mov    $0x2,%ecx
    7be0:	ba 0a 00 00 00       	mov    $0xa,%edx
    7be5:	e8 d6 97 ff ff       	callq  13c0 <l2cap_send_cmd>
}
    7bea:	48 83 c4 10          	add    $0x10,%rsp
    7bee:	5b                   	pop    %rbx
    7bef:	41 5c                	pop    %r12
    7bf1:	5d                   	pop    %rbp
    7bf2:	c3                   	retq   
    7bf3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		l2cap_chan_ready(chan);
    7bf8:	e8 63 a8 ff ff       	callq  2460 <l2cap_chan_ready>
		return;
    7bfd:	e9 6e ff ff ff       	jmpq   7b70 <l2cap_do_start+0x30>
    7c02:	0f 1f 40 00          	nopl   0x0(%rax)
    7c06:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    7c0d:	00 00 00 

0000000000007c10 <l2cap_connect_req>:
{
    7c10:	55                   	push   %rbp
    7c11:	48 89 e5             	mov    %rsp,%rbp
    7c14:	41 57                	push   %r15
    7c16:	41 56                	push   %r14
    7c18:	41 55                	push   %r13
    7c1a:	41 54                	push   %r12
    7c1c:	53                   	push   %rbx
    7c1d:	48 89 fb             	mov    %rdi,%rbx
    7c20:	48 81 ec d8 00 00 00 	sub    $0xd8,%rsp
    7c27:	48 89 b5 28 ff ff ff 	mov    %rsi,-0xd8(%rbp)
	u16 dcid = 0, scid = __le16_to_cpu(req->scid);
    7c2e:	44 0f b7 72 02       	movzwl 0x2(%rdx),%r14d
{
    7c33:	65 48 8b 04 25 28 00 	mov    %gs:0x28,%rax
    7c3a:	00 00 
    7c3c:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    7c40:	31 c0                	xor    %eax,%eax
	BT_DBG("psm 0x%2.2x scid 0x%4.4x", __le16_to_cpu(psm), scid);
    7c42:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 7c49 <l2cap_connect_req+0x39>
	__le16 psm = req->psm;
    7c49:	44 0f b7 22          	movzwl (%rdx),%r12d
	BT_DBG("psm 0x%2.2x scid 0x%4.4x", __le16_to_cpu(psm), scid);
    7c4d:	0f 85 86 05 00 00    	jne    81d9 <l2cap_connect_req+0x5c9>
    7c53:	45 0f b7 ec          	movzwl %r12w,%r13d
	pchan = l2cap_global_chan_by_psm(BT_LISTEN, psm, conn->src, conn->dst);
    7c57:	48 8b 4b 10          	mov    0x10(%rbx),%rcx
    7c5b:	48 8b 53 18          	mov    0x18(%rbx),%rdx
    7c5f:	44 89 ee             	mov    %r13d,%esi
    7c62:	bf 04 00 00 00       	mov    $0x4,%edi
    7c67:	e8 b4 8c ff ff       	callq  920 <l2cap_global_chan_by_psm>
	if (!pchan) {
    7c6c:	48 85 c0             	test   %rax,%rax
	pchan = l2cap_global_chan_by_psm(BT_LISTEN, psm, conn->src, conn->dst);
    7c6f:	49 89 c5             	mov    %rax,%r13
	if (!pchan) {
    7c72:	0f 84 18 02 00 00    	je     7e90 <l2cap_connect_req+0x280>
	parent = pchan->sk;
    7c78:	4c 8b 38             	mov    (%rax),%r15
	mutex_lock(&conn->chan_lock);
    7c7b:	48 8d 83 40 01 00 00 	lea    0x140(%rbx),%rax
    7c82:	48 89 c7             	mov    %rax,%rdi
    7c85:	48 89 85 20 ff ff ff 	mov    %rax,-0xe0(%rbp)
    7c8c:	e8 00 00 00 00       	callq  7c91 <l2cap_connect_req+0x81>
    7c91:	31 f6                	xor    %esi,%esi
    7c93:	4c 89 ff             	mov    %r15,%rdi
    7c96:	e8 00 00 00 00       	callq  7c9b <l2cap_connect_req+0x8b>
	if (psm != cpu_to_le16(0x0001) &&
    7c9b:	66 41 83 fc 01       	cmp    $0x1,%r12w
    7ca0:	74 4e                	je     7cf0 <l2cap_connect_req+0xe0>
				!hci_conn_check_link_mode(conn->hcon)) {
    7ca2:	48 8b 3b             	mov    (%rbx),%rdi
    7ca5:	e8 00 00 00 00       	callq  7caa <l2cap_connect_req+0x9a>
	if (psm != cpu_to_le16(0x0001) &&
    7caa:	85 c0                	test   %eax,%eax
    7cac:	75 42                	jne    7cf0 <l2cap_connect_req+0xe0>
		goto response;
    7cae:	45 31 c0             	xor    %r8d,%r8d
    7cb1:	41 b9 03 00 00 00    	mov    $0x3,%r9d
	u16 dcid = 0, scid = __le16_to_cpu(req->scid);
    7cb7:	45 31 d2             	xor    %r10d,%r10d
		conn->disc_reason = HCI_ERROR_AUTH_FAILURE;
    7cba:	c6 83 b5 00 00 00 05 	movb   $0x5,0xb5(%rbx)
		goto response;
    7cc1:	45 31 e4             	xor    %r12d,%r12d
    7cc4:	66 44 89 85 08 ff ff 	mov    %r8w,-0xf8(%rbp)
    7ccb:	ff 
    7ccc:	66 44 89 8d 10 ff ff 	mov    %r9w,-0xf0(%rbp)
    7cd3:	ff 
	u16 dcid = 0, scid = __le16_to_cpu(req->scid);
    7cd4:	66 44 89 95 18 ff ff 	mov    %r10w,-0xe8(%rbp)
    7cdb:	ff 
	struct l2cap_chan *chan = NULL, *pchan;
    7cdc:	45 31 ed             	xor    %r13d,%r13d
		result = L2CAP_CR_SEC_BLOCK;
    7cdf:	c7 85 04 ff ff ff 03 	movl   $0x3,-0xfc(%rbp)
    7ce6:	00 00 00 
		goto response;
    7ce9:	eb 56                	jmp    7d41 <l2cap_connect_req+0x131>
    7ceb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
	return sk->sk_ack_backlog > sk->sk_max_ack_backlog;
    7cf0:	41 0f b7 87 84 01 00 	movzwl 0x184(%r15),%eax
    7cf7:	00 
	if (sk_acceptq_is_full(parent)) {
    7cf8:	66 41 3b 87 86 01 00 	cmp    0x186(%r15),%ax
    7cff:	00 
    7d00:	0f 86 da 01 00 00    	jbe    7ee0 <l2cap_connect_req+0x2d0>
		BT_DBG("backlog full %d", parent->sk_ack_backlog);
    7d06:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 7d0d <l2cap_connect_req+0xfd>
    7d0d:	0f 85 eb 04 00 00    	jne    81fe <l2cap_connect_req+0x5ee>
    7d13:	31 c9                	xor    %ecx,%ecx
    7d15:	be 04 00 00 00       	mov    $0x4,%esi
	u16 dcid = 0, scid = __le16_to_cpu(req->scid);
    7d1a:	31 ff                	xor    %edi,%edi
		BT_DBG("backlog full %d", parent->sk_ack_backlog);
    7d1c:	45 31 e4             	xor    %r12d,%r12d
    7d1f:	66 89 8d 08 ff ff ff 	mov    %cx,-0xf8(%rbp)
    7d26:	66 89 b5 10 ff ff ff 	mov    %si,-0xf0(%rbp)
	u16 dcid = 0, scid = __le16_to_cpu(req->scid);
    7d2d:	66 89 bd 18 ff ff ff 	mov    %di,-0xe8(%rbp)
	result = L2CAP_CR_NO_MEM;
    7d34:	c7 85 04 ff ff ff 04 	movl   $0x4,-0xfc(%rbp)
    7d3b:	00 00 00 
	struct l2cap_chan *chan = NULL, *pchan;
    7d3e:	45 31 ed             	xor    %r13d,%r13d
	release_sock(parent);
    7d41:	4c 89 ff             	mov    %r15,%rdi
    7d44:	e8 00 00 00 00       	callq  7d49 <l2cap_connect_req+0x139>
	mutex_unlock(&conn->chan_lock);
    7d49:	48 8b bd 20 ff ff ff 	mov    -0xe0(%rbp),%rdi
    7d50:	e8 00 00 00 00       	callq  7d55 <l2cap_connect_req+0x145>
	rsp.dcid   = cpu_to_le16(dcid);
    7d55:	0f b7 85 18 ff ff ff 	movzwl -0xe8(%rbp),%eax
	l2cap_send_cmd(conn, cmd->ident, L2CAP_CONN_RSP, sizeof(rsp), &rsp);
    7d5c:	4c 8d 85 40 ff ff ff 	lea    -0xc0(%rbp),%r8
    7d63:	b9 08 00 00 00       	mov    $0x8,%ecx
    7d68:	ba 03 00 00 00       	mov    $0x3,%edx
    7d6d:	48 89 df             	mov    %rbx,%rdi
	rsp.scid   = cpu_to_le16(scid);
    7d70:	66 44 89 b5 42 ff ff 	mov    %r14w,-0xbe(%rbp)
    7d77:	ff 
	rsp.dcid   = cpu_to_le16(dcid);
    7d78:	66 89 85 40 ff ff ff 	mov    %ax,-0xc0(%rbp)
	rsp.result = cpu_to_le16(result);
    7d7f:	0f b7 85 10 ff ff ff 	movzwl -0xf0(%rbp),%eax
    7d86:	66 89 85 44 ff ff ff 	mov    %ax,-0xbc(%rbp)
	rsp.status = cpu_to_le16(status);
    7d8d:	0f b7 85 08 ff ff ff 	movzwl -0xf8(%rbp),%eax
    7d94:	66 89 85 46 ff ff ff 	mov    %ax,-0xba(%rbp)
	l2cap_send_cmd(conn, cmd->ident, L2CAP_CONN_RSP, sizeof(rsp), &rsp);
    7d9b:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    7da2:	0f b6 70 01          	movzbl 0x1(%rax),%esi
    7da6:	e8 15 96 ff ff       	callq  13c0 <l2cap_send_cmd>
	if (result == L2CAP_CR_PEND && status == L2CAP_CS_NO_INFO) {
    7dab:	45 84 e4             	test   %r12b,%r12b
    7dae:	74 4e                	je     7dfe <l2cap_connect_req+0x1ee>
		conn->info_state |= L2CAP_INFO_FEAT_MASK_REQ_SENT;
    7db0:	80 4b 29 04          	orb    $0x4,0x29(%rbx)
		info.type = cpu_to_le16(L2CAP_IT_FEAT_MASK);
    7db4:	bf 02 00 00 00       	mov    $0x2,%edi
    7db9:	66 89 bd 3e ff ff ff 	mov    %di,-0xc2(%rbp)
		conn->info_ident = l2cap_get_ident(conn);
    7dc0:	48 89 df             	mov    %rbx,%rdi
    7dc3:	e8 e8 86 ff ff       	callq  4b0 <l2cap_get_ident>
		schedule_delayed_work(&conn->info_timer, L2CAP_INFO_TIMEOUT);
    7dc8:	bf a0 0f 00 00       	mov    $0xfa0,%edi
		conn->info_ident = l2cap_get_ident(conn);
    7dcd:	88 43 2a             	mov    %al,0x2a(%rbx)
		schedule_delayed_work(&conn->info_timer, L2CAP_INFO_TIMEOUT);
    7dd0:	e8 00 00 00 00       	callq  7dd5 <l2cap_connect_req+0x1c5>
    7dd5:	48 8d 7b 30          	lea    0x30(%rbx),%rdi
    7dd9:	48 89 c6             	mov    %rax,%rsi
    7ddc:	e8 00 00 00 00       	callq  7de1 <l2cap_connect_req+0x1d1>
		l2cap_send_cmd(conn, conn->info_ident,
    7de1:	0f b6 73 2a          	movzbl 0x2a(%rbx),%esi
    7de5:	4c 8d 85 3e ff ff ff 	lea    -0xc2(%rbp),%r8
    7dec:	b9 02 00 00 00       	mov    $0x2,%ecx
    7df1:	ba 0a 00 00 00       	mov    $0xa,%edx
    7df6:	48 89 df             	mov    %rbx,%rdi
    7df9:	e8 c2 95 ff ff       	callq  13c0 <l2cap_send_cmd>
	if (chan && !test_bit(CONF_REQ_SENT, &chan->conf_state) &&
    7dfe:	4d 85 ed             	test   %r13,%r13
    7e01:	74 5d                	je     7e60 <l2cap_connect_req+0x250>
    7e03:	49 8b 85 80 00 00 00 	mov    0x80(%r13),%rax
    7e0a:	a8 01                	test   $0x1,%al
    7e0c:	75 52                	jne    7e60 <l2cap_connect_req+0x250>
    7e0e:	8b b5 04 ff ff ff    	mov    -0xfc(%rbp),%esi
    7e14:	85 f6                	test   %esi,%esi
    7e16:	75 48                	jne    7e60 <l2cap_connect_req+0x250>
		asm volatile(LOCK_PREFIX "orb %1,%0"
    7e18:	f0 41 80 8d 80 00 00 	lock orb $0x1,0x80(%r13)
    7e1f:	00 01 
					l2cap_build_conf_req(chan, buf), buf);
    7e21:	48 8d b5 48 ff ff ff 	lea    -0xb8(%rbp),%rsi
    7e28:	4c 89 ef             	mov    %r13,%rdi
    7e2b:	e8 40 98 ff ff       	callq  1670 <l2cap_build_conf_req>
		l2cap_send_cmd(conn, l2cap_get_ident(conn), L2CAP_CONF_REQ,
    7e30:	48 89 df             	mov    %rbx,%rdi
					l2cap_build_conf_req(chan, buf), buf);
    7e33:	41 89 c4             	mov    %eax,%r12d
		l2cap_send_cmd(conn, l2cap_get_ident(conn), L2CAP_CONF_REQ,
    7e36:	e8 75 86 ff ff       	callq  4b0 <l2cap_get_ident>
    7e3b:	4c 8d 85 48 ff ff ff 	lea    -0xb8(%rbp),%r8
    7e42:	41 0f b7 cc          	movzwl %r12w,%ecx
    7e46:	0f b6 f0             	movzbl %al,%esi
    7e49:	ba 04 00 00 00       	mov    $0x4,%edx
    7e4e:	48 89 df             	mov    %rbx,%rdi
    7e51:	e8 6a 95 ff ff       	callq  13c0 <l2cap_send_cmd>
		chan->num_conf_req++;
    7e56:	41 80 45 6d 01       	addb   $0x1,0x6d(%r13)
    7e5b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
}
    7e60:	31 c0                	xor    %eax,%eax
    7e62:	48 8b 75 c8          	mov    -0x38(%rbp),%rsi
    7e66:	65 48 33 34 25 28 00 	xor    %gs:0x28,%rsi
    7e6d:	00 00 
    7e6f:	0f 85 5f 03 00 00    	jne    81d4 <l2cap_connect_req+0x5c4>
    7e75:	48 81 c4 d8 00 00 00 	add    $0xd8,%rsp
    7e7c:	5b                   	pop    %rbx
    7e7d:	41 5c                	pop    %r12
    7e7f:	41 5d                	pop    %r13
    7e81:	41 5e                	pop    %r14
    7e83:	41 5f                	pop    %r15
    7e85:	5d                   	pop    %rbp
    7e86:	c3                   	retq   
    7e87:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    7e8e:	00 00 
	rsp.dcid   = cpu_to_le16(dcid);
    7e90:	31 c0                	xor    %eax,%eax
	rsp.status = cpu_to_le16(status);
    7e92:	31 c9                	xor    %ecx,%ecx
	rsp.result = cpu_to_le16(result);
    7e94:	ba 02 00 00 00       	mov    $0x2,%edx
	rsp.dcid   = cpu_to_le16(dcid);
    7e99:	66 89 85 40 ff ff ff 	mov    %ax,-0xc0(%rbp)
	l2cap_send_cmd(conn, cmd->ident, L2CAP_CONN_RSP, sizeof(rsp), &rsp);
    7ea0:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
    7ea7:	4c 8d 85 40 ff ff ff 	lea    -0xc0(%rbp),%r8
	rsp.result = cpu_to_le16(result);
    7eae:	66 89 95 44 ff ff ff 	mov    %dx,-0xbc(%rbp)
	rsp.status = cpu_to_le16(status);
    7eb5:	66 89 8d 46 ff ff ff 	mov    %cx,-0xba(%rbp)
	l2cap_send_cmd(conn, cmd->ident, L2CAP_CONN_RSP, sizeof(rsp), &rsp);
    7ebc:	ba 03 00 00 00       	mov    $0x3,%edx
    7ec1:	b9 08 00 00 00       	mov    $0x8,%ecx
    7ec6:	48 89 df             	mov    %rbx,%rdi
	rsp.scid   = cpu_to_le16(scid);
    7ec9:	66 44 89 b5 42 ff ff 	mov    %r14w,-0xbe(%rbp)
    7ed0:	ff 
	l2cap_send_cmd(conn, cmd->ident, L2CAP_CONN_RSP, sizeof(rsp), &rsp);
    7ed1:	0f b6 70 01          	movzbl 0x1(%rax),%esi
    7ed5:	e8 e6 94 ff ff       	callq  13c0 <l2cap_send_cmd>
    7eda:	eb 84                	jmp    7e60 <l2cap_connect_req+0x250>
    7edc:	0f 1f 40 00          	nopl   0x0(%rax)
	chan = pchan->ops->new_connection(pchan->data);
    7ee0:	49 8b 85 40 03 00 00 	mov    0x340(%r13),%rax
    7ee7:	49 8b bd 38 03 00 00 	mov    0x338(%r13),%rdi
    7eee:	ff 50 08             	callq  *0x8(%rax)
	if (!chan)
    7ef1:	48 85 c0             	test   %rax,%rax
	chan = pchan->ops->new_connection(pchan->data);
    7ef4:	49 89 c5             	mov    %rax,%r13
	if (!chan)
    7ef7:	0f 84 16 fe ff ff    	je     7d13 <l2cap_connect_req+0x103>
	list_for_each_entry(c, &conn->chan_l, list) {
    7efd:	48 8b 8b 30 01 00 00 	mov    0x130(%rbx),%rcx
    7f04:	48 8d 93 30 01 00 00 	lea    0x130(%rbx),%rdx
	sk = chan->sk;
    7f0b:	4c 8b 08             	mov    (%rax),%r9
	list_for_each_entry(c, &conn->chan_l, list) {
    7f0e:	48 39 ca             	cmp    %rcx,%rdx
    7f11:	48 8d 81 e8 fc ff ff 	lea    -0x318(%rcx),%rax
    7f18:	75 19                	jne    7f33 <l2cap_connect_req+0x323>
    7f1a:	eb 74                	jmp    7f90 <l2cap_connect_req+0x380>
    7f1c:	0f 1f 40 00          	nopl   0x0(%rax)
    7f20:	48 8b 88 18 03 00 00 	mov    0x318(%rax),%rcx
    7f27:	48 39 ca             	cmp    %rcx,%rdx
    7f2a:	48 8d 81 e8 fc ff ff 	lea    -0x318(%rcx),%rax
    7f31:	74 5d                	je     7f90 <l2cap_connect_req+0x380>
		if (c->dcid == cid)
    7f33:	66 44 3b b1 02 fd ff 	cmp    -0x2fe(%rcx),%r14w
    7f3a:	ff 
    7f3b:	75 e3                	jne    7f20 <l2cap_connect_req+0x310>
	if (__l2cap_get_chan_by_dcid(conn, scid)) {
    7f3d:	48 85 c0             	test   %rax,%rax
    7f40:	74 4e                	je     7f90 <l2cap_connect_req+0x380>
	asm volatile("bts %1,%0" : ADDR : "Ir" (nr) : "memory");
    7f42:	41 0f ba a9 e8 00 00 	btsl   $0x8,0xe8(%r9)
    7f49:	00 08 
		chan->ops->close(chan->data);
    7f4b:	49 8b 85 40 03 00 00 	mov    0x340(%r13),%rax
    7f52:	49 8b bd 38 03 00 00 	mov    0x338(%r13),%rdi
		goto response;
    7f59:	45 31 e4             	xor    %r12d,%r12d
		chan->ops->close(chan->data);
    7f5c:	ff 50 18             	callq  *0x18(%rax)
		goto response;
    7f5f:	31 c0                	xor    %eax,%eax
	u16 dcid = 0, scid = __le16_to_cpu(req->scid);
    7f61:	31 d2                	xor    %edx,%edx
	result = L2CAP_CR_NO_MEM;
    7f63:	c7 85 04 ff ff ff 04 	movl   $0x4,-0xfc(%rbp)
    7f6a:	00 00 00 
		goto response;
    7f6d:	66 89 85 08 ff ff ff 	mov    %ax,-0xf8(%rbp)
    7f74:	b8 04 00 00 00       	mov    $0x4,%eax
	u16 dcid = 0, scid = __le16_to_cpu(req->scid);
    7f79:	66 89 95 18 ff ff ff 	mov    %dx,-0xe8(%rbp)
		goto response;
    7f80:	66 89 85 10 ff ff ff 	mov    %ax,-0xf0(%rbp)
    7f87:	e9 b5 fd ff ff       	jmpq   7d41 <l2cap_connect_req+0x131>
    7f8c:	0f 1f 40 00          	nopl   0x0(%rax)
    7f90:	4c 89 8d 18 ff ff ff 	mov    %r9,-0xe8(%rbp)
	hci_conn_hold(conn->hcon);
    7f97:	48 8b 13             	mov    (%rbx),%rdx
	asm volatile(LOCK_PREFIX "incl %0"
    7f9a:	f0 ff 42 10          	lock incl 0x10(%rdx)
	ret = del_timer_sync(&work->timer);
    7f9e:	48 8d ba a0 00 00 00 	lea    0xa0(%rdx),%rdi
    7fa5:	48 89 95 10 ff ff ff 	mov    %rdx,-0xf0(%rbp)
    7fac:	e8 00 00 00 00       	callq  7fb1 <l2cap_connect_req+0x3a1>
	if (ret)
    7fb1:	85 c0                	test   %eax,%eax
    7fb3:	4c 8b 8d 18 ff ff ff 	mov    -0xe8(%rbp),%r9
    7fba:	74 0f                	je     7fcb <l2cap_connect_req+0x3bb>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    7fbc:	48 8b 95 10 ff ff ff 	mov    -0xf0(%rbp),%rdx
    7fc3:	f0 80 a2 80 00 00 00 	lock andb $0xfe,0x80(%rdx)
    7fca:	fe 
	memcpy(dst, src, sizeof(bdaddr_t));
    7fcb:	48 8b 43 18          	mov    0x18(%rbx),%rax
	bt_accept_enqueue(parent, sk);
    7fcf:	4c 89 ce             	mov    %r9,%rsi
    7fd2:	4c 89 ff             	mov    %r15,%rdi
    7fd5:	4c 89 8d 10 ff ff ff 	mov    %r9,-0xf0(%rbp)
    7fdc:	8b 10                	mov    (%rax),%edx
    7fde:	41 89 91 88 02 00 00 	mov    %edx,0x288(%r9)
    7fe5:	0f b7 40 04          	movzwl 0x4(%rax),%eax
    7fe9:	66 41 89 81 8c 02 00 	mov    %ax,0x28c(%r9)
    7ff0:	00 
    7ff1:	48 8b 43 10          	mov    0x10(%rbx),%rax
    7ff5:	8b 10                	mov    (%rax),%edx
    7ff7:	41 89 91 8e 02 00 00 	mov    %edx,0x28e(%r9)
    7ffe:	0f b7 40 04          	movzwl 0x4(%rax),%eax
    8002:	66 41 89 81 92 02 00 	mov    %ax,0x292(%r9)
    8009:	00 
	chan->psm  = psm;
    800a:	66 45 89 65 18       	mov    %r12w,0x18(%r13)
	__set_chan_timer(chan, sk->sk_sndtimeo);
    800f:	4d 8d a5 f0 00 00 00 	lea    0xf0(%r13),%r12
	chan->dcid = scid;
    8016:	66 45 89 75 1a       	mov    %r14w,0x1a(%r13)
	bt_accept_enqueue(parent, sk);
    801b:	e8 00 00 00 00       	callq  8020 <l2cap_connect_req+0x410>
	__l2cap_chan_add(conn, chan);
    8020:	4c 89 ee             	mov    %r13,%rsi
    8023:	48 89 df             	mov    %rbx,%rdi
    8026:	e8 b5 82 ff ff       	callq  2e0 <__l2cap_chan_add>
	dcid = chan->scid;
    802b:	41 0f b7 45 1c       	movzwl 0x1c(%r13),%eax
	__set_chan_timer(chan, sk->sk_sndtimeo);
    8030:	4c 8b 8d 10 ff ff ff 	mov    -0xf0(%rbp),%r9
	BT_DBG("chan %p state %s timeout %ld", chan,
    8037:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 803e <l2cap_connect_req+0x42e>
	dcid = chan->scid;
    803e:	66 89 85 18 ff ff ff 	mov    %ax,-0xe8(%rbp)
	__set_chan_timer(chan, sk->sk_sndtimeo);
    8045:	49 8b 81 a8 01 00 00 	mov    0x1a8(%r9),%rax
    804c:	48 89 85 10 ff ff ff 	mov    %rax,-0xf0(%rbp)
    8053:	0f 85 c2 01 00 00    	jne    821b <l2cap_connect_req+0x60b>
	ret = del_timer_sync(&work->timer);
    8059:	49 8d bd 10 01 00 00 	lea    0x110(%r13),%rdi
    8060:	4c 89 8d 08 ff ff ff 	mov    %r9,-0xf8(%rbp)
    8067:	e8 00 00 00 00       	callq  806c <l2cap_connect_req+0x45c>
	if (ret)
    806c:	85 c0                	test   %eax,%eax
    806e:	4c 8b 8d 08 ff ff ff 	mov    -0xf8(%rbp),%r9
    8075:	0f 84 e3 00 00 00    	je     815e <l2cap_connect_req+0x54e>
    807b:	f0 41 80 24 24 fe    	lock andb $0xfe,(%r12)
	schedule_delayed_work(work, timeout);
    8081:	48 8b b5 10 ff ff ff 	mov    -0xf0(%rbp),%rsi
    8088:	4c 89 e7             	mov    %r12,%rdi
    808b:	4c 89 8d 08 ff ff ff 	mov    %r9,-0xf8(%rbp)
    8092:	e8 00 00 00 00       	callq  8097 <l2cap_connect_req+0x487>
	chan->ident = cmd->ident;
    8097:	48 8b 85 28 ff ff ff 	mov    -0xd8(%rbp),%rax
	if (conn->info_state & L2CAP_INFO_FEAT_MASK_REQ_DONE) {
    809e:	4c 8b 8d 08 ff ff ff 	mov    -0xf8(%rbp),%r9
	chan->ident = cmd->ident;
    80a5:	0f b6 40 01          	movzbl 0x1(%rax),%eax
    80a9:	41 88 45 2b          	mov    %al,0x2b(%r13)
	if (conn->info_state & L2CAP_INFO_FEAT_MASK_REQ_DONE) {
    80ad:	f6 43 29 08          	testb  $0x8,0x29(%rbx)
    80b1:	74 70                	je     8123 <l2cap_connect_req+0x513>
		if (l2cap_chan_check_security(chan)) {
    80b3:	4c 89 ef             	mov    %r13,%rdi
    80b6:	4c 89 8d 10 ff ff ff 	mov    %r9,-0xf0(%rbp)
    80bd:	e8 00 00 00 00       	callq  80c2 <l2cap_connect_req+0x4b2>
    80c2:	85 c0                	test   %eax,%eax
    80c4:	0f 84 cf 00 00 00    	je     8199 <l2cap_connect_req+0x589>
		(addr[nr / BITS_PER_LONG])) != 0;
    80ca:	4c 8b 8d 10 ff ff ff 	mov    -0xf0(%rbp),%r9
    80d1:	49 8b 81 b0 02 00 00 	mov    0x2b0(%r9),%rax
			if (test_bit(BT_SK_DEFER_SETUP, &bt_sk(sk)->flags)) {
    80d8:	a8 01                	test   $0x1,%al
    80da:	0f 84 88 00 00 00    	je     8168 <l2cap_connect_req+0x558>
				__l2cap_state_change(chan, BT_CONNECT2);
    80e0:	be 06 00 00 00       	mov    $0x6,%esi
    80e5:	4c 89 ef             	mov    %r13,%rdi
    80e8:	45 31 e4             	xor    %r12d,%r12d
    80eb:	e8 a0 7f ff ff       	callq  90 <__l2cap_state_change>
				parent->sk_data_ready(parent, 0);
    80f0:	31 f6                	xor    %esi,%esi
    80f2:	4c 89 ff             	mov    %r15,%rdi
    80f5:	41 ff 97 60 02 00 00 	callq  *0x260(%r15)
    80fc:	b8 02 00 00 00       	mov    $0x2,%eax
				result = L2CAP_CR_PEND;
    8101:	c7 85 04 ff ff ff 01 	movl   $0x1,-0xfc(%rbp)
    8108:	00 00 00 
    810b:	66 89 85 08 ff ff ff 	mov    %ax,-0xf8(%rbp)
    8112:	b8 01 00 00 00       	mov    $0x1,%eax
    8117:	66 89 85 10 ff ff ff 	mov    %ax,-0xf0(%rbp)
    811e:	e9 1e fc ff ff       	jmpq   7d41 <l2cap_connect_req+0x131>
		__l2cap_state_change(chan, BT_CONNECT2);
    8123:	be 06 00 00 00       	mov    $0x6,%esi
    8128:	4c 89 ef             	mov    %r13,%rdi
    812b:	41 bc 01 00 00 00    	mov    $0x1,%r12d
    8131:	e8 5a 7f ff ff       	callq  90 <__l2cap_state_change>
    8136:	45 31 c0             	xor    %r8d,%r8d
    8139:	41 b9 01 00 00 00    	mov    $0x1,%r9d
		result = L2CAP_CR_PEND;
    813f:	c7 85 04 ff ff ff 01 	movl   $0x1,-0xfc(%rbp)
    8146:	00 00 00 
		__l2cap_state_change(chan, BT_CONNECT2);
    8149:	66 44 89 85 08 ff ff 	mov    %r8w,-0xf8(%rbp)
    8150:	ff 
    8151:	66 44 89 8d 10 ff ff 	mov    %r9w,-0xf0(%rbp)
    8158:	ff 
    8159:	e9 e3 fb ff ff       	jmpq   7d41 <l2cap_connect_req+0x131>
    815e:	f0 41 ff 45 14       	lock incl 0x14(%r13)
    8163:	e9 19 ff ff ff       	jmpq   8081 <l2cap_connect_req+0x471>
				__l2cap_state_change(chan, BT_CONFIG);
    8168:	be 07 00 00 00       	mov    $0x7,%esi
    816d:	4c 89 ef             	mov    %r13,%rdi
    8170:	45 31 e4             	xor    %r12d,%r12d
    8173:	e8 18 7f ff ff       	callq  90 <__l2cap_state_change>
    8178:	31 c0                	xor    %eax,%eax
				result = L2CAP_CR_SUCCESS;
    817a:	c7 85 04 ff ff ff 00 	movl   $0x0,-0xfc(%rbp)
    8181:	00 00 00 
				__l2cap_state_change(chan, BT_CONFIG);
    8184:	66 89 85 08 ff ff ff 	mov    %ax,-0xf8(%rbp)
    818b:	31 c0                	xor    %eax,%eax
    818d:	66 89 85 10 ff ff ff 	mov    %ax,-0xf0(%rbp)
    8194:	e9 a8 fb ff ff       	jmpq   7d41 <l2cap_connect_req+0x131>
			__l2cap_state_change(chan, BT_CONNECT2);
    8199:	be 06 00 00 00       	mov    $0x6,%esi
    819e:	4c 89 ef             	mov    %r13,%rdi
    81a1:	45 31 e4             	xor    %r12d,%r12d
    81a4:	e8 e7 7e ff ff       	callq  90 <__l2cap_state_change>
    81a9:	41 ba 01 00 00 00    	mov    $0x1,%r10d
    81af:	41 bb 01 00 00 00    	mov    $0x1,%r11d
			result = L2CAP_CR_PEND;
    81b5:	c7 85 04 ff ff ff 01 	movl   $0x1,-0xfc(%rbp)
    81bc:	00 00 00 
			__l2cap_state_change(chan, BT_CONNECT2);
    81bf:	66 44 89 95 08 ff ff 	mov    %r10w,-0xf8(%rbp)
    81c6:	ff 
    81c7:	66 44 89 9d 10 ff ff 	mov    %r11w,-0xf0(%rbp)
    81ce:	ff 
    81cf:	e9 6d fb ff ff       	jmpq   7d41 <l2cap_connect_req+0x131>
}
    81d4:	e8 00 00 00 00       	callq  81d9 <l2cap_connect_req+0x5c9>
	BT_DBG("psm 0x%2.2x scid 0x%4.4x", __le16_to_cpu(psm), scid);
    81d9:	45 0f b7 ec          	movzwl %r12w,%r13d
    81dd:	41 0f b7 ce          	movzwl %r14w,%ecx
    81e1:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    81e8:	44 89 ea             	mov    %r13d,%edx
    81eb:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    81f2:	31 c0                	xor    %eax,%eax
    81f4:	e8 00 00 00 00       	callq  81f9 <l2cap_connect_req+0x5e9>
    81f9:	e9 59 fa ff ff       	jmpq   7c57 <l2cap_connect_req+0x47>
		BT_DBG("backlog full %d", parent->sk_ack_backlog);
    81fe:	0f b7 d0             	movzwl %ax,%edx
    8201:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    8208:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    820f:	31 c0                	xor    %eax,%eax
    8211:	e8 00 00 00 00       	callq  8216 <l2cap_connect_req+0x606>
    8216:	e9 f8 fa ff ff       	jmpq   7d13 <l2cap_connect_req+0x103>
	switch (state) {
    821b:	41 0f b6 45 10       	movzbl 0x10(%r13),%eax
    8220:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    8227:	83 e8 01             	sub    $0x1,%eax
    822a:	83 f8 08             	cmp    $0x8,%eax
    822d:	77 08                	ja     8237 <l2cap_connect_req+0x627>
    822f:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    8236:	00 
	BT_DBG("chan %p state %s timeout %ld", chan,
    8237:	4c 8b 85 10 ff ff ff 	mov    -0xf0(%rbp),%r8
    823e:	4c 89 ea             	mov    %r13,%rdx
    8241:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    8248:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    824f:	31 c0                	xor    %eax,%eax
    8251:	4c 89 8d 08 ff ff ff 	mov    %r9,-0xf8(%rbp)
    8258:	e8 00 00 00 00       	callq  825d <l2cap_connect_req+0x64d>
    825d:	4c 8b 8d 08 ff ff ff 	mov    -0xf8(%rbp),%r9
    8264:	e9 f0 fd ff ff       	jmpq   8059 <l2cap_connect_req+0x449>
    8269:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000008270 <l2cap_sig_channel>:
{
    8270:	55                   	push   %rbp
    8271:	48 89 e5             	mov    %rsp,%rbp
    8274:	41 57                	push   %r15
    8276:	41 56                	push   %r14
    8278:	49 89 fe             	mov    %rdi,%r14
    827b:	41 55                	push   %r13
    827d:	41 54                	push   %r12
    827f:	53                   	push   %rbx
    8280:	48 83 ec 78          	sub    $0x78,%rsp
    8284:	48 89 75 90          	mov    %rsi,-0x70(%rbp)
	u8 *data = skb->data;
    8288:	4c 8b 8e e0 00 00 00 	mov    0xe0(%rsi),%r9
{
    828f:	65 48 8b 3c 25 28 00 	mov    %gs:0x28,%rdi
    8296:	00 00 
    8298:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
    829c:	31 ff                	xor    %edi,%edi
	BT_DBG("conn %p", conn);
    829e:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 82a5 <l2cap_sig_channel+0x35>
	int len = skb->len;
    82a5:	44 8b 6e 68          	mov    0x68(%rsi),%r13d
	BT_DBG("conn %p", conn);
    82a9:	0f 85 d4 0d 00 00    	jne    9083 <l2cap_sig_channel+0xe13>
	mutex_lock(&conn->chan_lock);
    82af:	49 8d 86 40 01 00 00 	lea    0x140(%r14),%rax
    82b6:	4c 89 4d a8          	mov    %r9,-0x58(%rbp)
    82ba:	48 89 c7             	mov    %rax,%rdi
    82bd:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    82c1:	e8 00 00 00 00       	callq  82c6 <l2cap_sig_channel+0x56>
	list_for_each_entry(chan, &conn->chan_l, list) {
    82c6:	49 8b 86 30 01 00 00 	mov    0x130(%r14),%rax
    82cd:	49 8d be 30 01 00 00 	lea    0x130(%r14),%rdi
    82d4:	4c 8b 4d a8          	mov    -0x58(%rbp),%r9
    82d8:	48 89 7d 98          	mov    %rdi,-0x68(%rbp)
    82dc:	48 39 c7             	cmp    %rax,%rdi
    82df:	48 8d 98 e8 fc ff ff 	lea    -0x318(%rax),%rbx
    82e6:	0f 84 7c 00 00 00    	je     8368 <l2cap_sig_channel+0xf8>
    82ec:	4c 89 4d a8          	mov    %r9,-0x58(%rbp)
    82f0:	44 89 6d 88          	mov    %r13d,-0x78(%rbp)
    82f4:	4c 8b 65 98          	mov    -0x68(%rbp),%r12
    82f8:	4c 8b 7d 90          	mov    -0x70(%rbp),%r15
    82fc:	eb 15                	jmp    8313 <l2cap_sig_channel+0xa3>
    82fe:	66 90                	xchg   %ax,%ax
    8300:	48 8b 83 18 03 00 00 	mov    0x318(%rbx),%rax
    8307:	49 39 c4             	cmp    %rax,%r12
    830a:	48 8d 98 e8 fc ff ff 	lea    -0x318(%rax),%rbx
    8311:	74 4d                	je     8360 <l2cap_sig_channel+0xf0>
		if (chan->chan_type != L2CAP_CHAN_RAW)
    8313:	80 7b 25 01          	cmpb   $0x1,0x25(%rbx)
		struct sock *sk = chan->sk;
    8317:	48 8b 03             	mov    (%rbx),%rax
		if (chan->chan_type != L2CAP_CHAN_RAW)
    831a:	75 e4                	jne    8300 <l2cap_sig_channel+0x90>
		if (skb->sk == sk)
    831c:	49 3b 47 18          	cmp    0x18(%r15),%rax
    8320:	74 de                	je     8300 <l2cap_sig_channel+0x90>
		nskb = skb_clone(skb, GFP_ATOMIC);
    8322:	be 20 00 00 00       	mov    $0x20,%esi
    8327:	4c 89 ff             	mov    %r15,%rdi
    832a:	e8 00 00 00 00       	callq  832f <l2cap_sig_channel+0xbf>
		if (!nskb)
    832f:	48 85 c0             	test   %rax,%rax
		nskb = skb_clone(skb, GFP_ATOMIC);
    8332:	49 89 c5             	mov    %rax,%r13
		if (!nskb)
    8335:	74 c9                	je     8300 <l2cap_sig_channel+0x90>
		if (chan->ops->recv(chan->data, nskb))
    8337:	48 8b 83 40 03 00 00 	mov    0x340(%rbx),%rax
    833e:	48 8b bb 38 03 00 00 	mov    0x338(%rbx),%rdi
    8345:	4c 89 ee             	mov    %r13,%rsi
    8348:	ff 50 10             	callq  *0x10(%rax)
    834b:	85 c0                	test   %eax,%eax
    834d:	74 b1                	je     8300 <l2cap_sig_channel+0x90>
			kfree_skb(nskb);
    834f:	4c 89 ef             	mov    %r13,%rdi
    8352:	e8 00 00 00 00       	callq  8357 <l2cap_sig_channel+0xe7>
    8357:	eb a7                	jmp    8300 <l2cap_sig_channel+0x90>
    8359:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    8360:	4c 8b 4d a8          	mov    -0x58(%rbp),%r9
    8364:	44 8b 6d 88          	mov    -0x78(%rbp),%r13d
	mutex_unlock(&conn->chan_lock);
    8368:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    836c:	4c 89 4d a8          	mov    %r9,-0x58(%rbp)
    8370:	e8 00 00 00 00       	callq  8375 <l2cap_sig_channel+0x105>
	while (len >= L2CAP_CMD_HDR_SIZE) {
    8375:	41 83 fd 03          	cmp    $0x3,%r13d
    8379:	4c 8b 4d a8          	mov    -0x58(%rbp),%r9
    837d:	0f 8e 9d 01 00 00    	jle    8520 <l2cap_sig_channel+0x2b0>
	ret = del_timer_sync(&work->timer);
    8383:	49 8d 46 50          	lea    0x50(%r14),%rax
		l2cap_send_cmd(conn, cmd->ident,
    8387:	4c 89 75 a8          	mov    %r14,-0x58(%rbp)
    838b:	48 89 85 68 ff ff ff 	mov    %rax,-0x98(%rbp)
    8392:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		memcpy(&cmd, data, L2CAP_CMD_HDR_SIZE);
    8398:	41 8b 19             	mov    (%r9),%ebx
		len  -= L2CAP_CMD_HDR_SIZE;
    839b:	41 83 ed 04          	sub    $0x4,%r13d
		data += L2CAP_CMD_HDR_SIZE;
    839f:	4d 8d 61 04          	lea    0x4(%r9),%r12
		memcpy(&cmd, data, L2CAP_CMD_HDR_SIZE);
    83a3:	89 5d b0             	mov    %ebx,-0x50(%rbp)
		cmd_len = le16_to_cpu(cmd.len);
    83a6:	c1 eb 10             	shr    $0x10,%ebx
		BT_DBG("code 0x%2.2x len %d id 0x%2.2x", cmd.code, cmd_len, cmd.ident);
    83a9:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 83b0 <l2cap_sig_channel+0x140>
    83b0:	0f 85 be 0a 00 00    	jne    8e74 <l2cap_sig_channel+0xc04>
    83b6:	44 0f b7 f3          	movzwl %bx,%r14d
		if (cmd_len > len || !cmd.ident) {
    83ba:	45 39 f5             	cmp    %r14d,%r13d
    83bd:	0f 8c 5d 02 00 00    	jl     8620 <l2cap_sig_channel+0x3b0>
    83c3:	0f b6 45 b1          	movzbl -0x4f(%rbp),%eax
    83c7:	84 c0                	test   %al,%al
    83c9:	0f 84 51 02 00 00    	je     8620 <l2cap_sig_channel+0x3b0>
		if (conn->hcon->type == LE_LINK)
    83cf:	48 8b 4d a8          	mov    -0x58(%rbp),%rcx
	switch (cmd->code) {
    83d3:	0f b6 75 b0          	movzbl -0x50(%rbp),%esi
		if (conn->hcon->type == LE_LINK)
    83d7:	4c 8b 39             	mov    (%rcx),%r15
    83da:	41 80 7f 21 80       	cmpb   $0x80,0x21(%r15)
    83df:	0f 84 fb 01 00 00    	je     85e0 <l2cap_sig_channel+0x370>
	switch (cmd->code) {
    83e5:	40 80 fe 11          	cmp    $0x11,%sil
    83e9:	0f 87 61 02 00 00    	ja     8650 <l2cap_sig_channel+0x3e0>
    83ef:	40 0f b6 d6          	movzbl %sil,%edx
    83f3:	ff 24 d5 00 00 00 00 	jmpq   *0x0(,%rdx,8)
    83fa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
	if (!(hcon->link_mode & HCI_LM_MASTER))
    8400:	41 f6 47 38 01       	testb  $0x1,0x38(%r15)
    8405:	0f 84 53 02 00 00    	je     865e <l2cap_sig_channel+0x3ee>
	if (cmd_len != sizeof(struct l2cap_conn_param_update_req))
    840b:	66 83 7d b2 08       	cmpw   $0x8,-0x4e(%rbp)
    8410:	0f 85 a2 07 00 00    	jne    8bb8 <l2cap_sig_channel+0x948>
	latency		= __le16_to_cpu(req->latency);
    8416:	41 0f b7 49 08       	movzwl 0x8(%r9),%ecx
	to_multiplier	= __le16_to_cpu(req->to_multiplier);
    841b:	41 0f b7 79 0a       	movzwl 0xa(%r9),%edi
	BT_DBG("min 0x%4.4x max 0x%4.4x latency: 0x%4.4x Timeout: 0x%4.4x",
    8420:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 8427 <l2cap_sig_channel+0x1b7>
	min		= __le16_to_cpu(req->min);
    8427:	45 0f b7 59 04       	movzwl 0x4(%r9),%r11d
	max		= __le16_to_cpu(req->max);
    842c:	45 0f b7 51 06       	movzwl 0x6(%r9),%r10d
	latency		= __le16_to_cpu(req->latency);
    8431:	66 89 8d 7c ff ff ff 	mov    %cx,-0x84(%rbp)
	to_multiplier	= __le16_to_cpu(req->to_multiplier);
    8438:	66 89 bd 7e ff ff ff 	mov    %di,-0x82(%rbp)
	BT_DBG("min 0x%4.4x max 0x%4.4x latency: 0x%4.4x Timeout: 0x%4.4x",
    843f:	0f 85 7f 0b 00 00    	jne    8fc4 <l2cap_sig_channel+0xd54>
    8445:	89 8d 78 ff ff ff    	mov    %ecx,-0x88(%rbp)
    844b:	41 0f b7 ca          	movzwl %r10w,%ecx
    844f:	89 7d 88             	mov    %edi,-0x78(%rbp)
    8452:	89 4d 80             	mov    %ecx,-0x80(%rbp)
    8455:	41 0f b7 cb          	movzwl %r11w,%ecx
    8459:	0f b6 f0             	movzbl %al,%esi
    845c:	89 8d 74 ff ff ff    	mov    %ecx,-0x8c(%rbp)
	memset(&rsp, 0, sizeof(rsp));
    8462:	31 ff                	xor    %edi,%edi
	if (min > max || min < 6 || max > 3200)
    8464:	66 45 39 d3          	cmp    %r10w,%r11w
	memset(&rsp, 0, sizeof(rsp));
    8468:	66 89 7d b4          	mov    %di,-0x4c(%rbp)
	if (min > max || min < 6 || max > 3200)
    846c:	0f 87 06 09 00 00    	ja     8d78 <l2cap_sig_channel+0xb08>
    8472:	66 41 83 fb 05       	cmp    $0x5,%r11w
    8477:	0f 86 fb 08 00 00    	jbe    8d78 <l2cap_sig_channel+0xb08>
    847d:	66 41 81 fa 80 0c    	cmp    $0xc80,%r10w
    8483:	0f 87 ef 08 00 00    	ja     8d78 <l2cap_sig_channel+0xb08>
	if (to_multiplier < 10 || to_multiplier > 3200)
    8489:	0f b7 95 7e ff ff ff 	movzwl -0x82(%rbp),%edx
    8490:	83 ea 0a             	sub    $0xa,%edx
    8493:	66 81 fa 76 0c       	cmp    $0xc76,%dx
    8498:	0f 87 da 08 00 00    	ja     8d78 <l2cap_sig_channel+0xb08>
	if (max >= to_multiplier * 8)
    849e:	8b 45 88             	mov    -0x78(%rbp),%eax
    84a1:	8b 4d 80             	mov    -0x80(%rbp),%ecx
    84a4:	c1 e0 03             	shl    $0x3,%eax
    84a7:	39 c8                	cmp    %ecx,%eax
    84a9:	0f 8e c9 08 00 00    	jle    8d78 <l2cap_sig_channel+0xb08>
	max_latency = (to_multiplier * 8 / max) - 1;
    84af:	99                   	cltd   
	if (latency > 499 || latency > max_latency)
    84b0:	0f b7 bd 7c ff ff ff 	movzwl -0x84(%rbp),%edi
	max_latency = (to_multiplier * 8 / max) - 1;
    84b7:	f7 f9                	idiv   %ecx
    84b9:	83 e8 01             	sub    $0x1,%eax
	if (latency > 499 || latency > max_latency)
    84bc:	66 39 c7             	cmp    %ax,%di
    84bf:	0f 87 b3 08 00 00    	ja     8d78 <l2cap_sig_channel+0xb08>
    84c5:	66 81 ff f3 01       	cmp    $0x1f3,%di
    84ca:	0f 87 a8 08 00 00    	ja     8d78 <l2cap_sig_channel+0xb08>
	l2cap_send_cmd(conn, cmd->ident, L2CAP_CONN_PARAM_UPDATE_RSP,
    84d0:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    84d4:	4c 8d 45 b4          	lea    -0x4c(%rbp),%r8
    84d8:	b9 02 00 00 00       	mov    $0x2,%ecx
    84dd:	ba 13 00 00 00       	mov    $0x13,%edx
    84e2:	e8 d9 8e ff ff       	callq  13c0 <l2cap_send_cmd>
		hci_le_conn_update(hcon, min, max, latency, to_multiplier);
    84e7:	44 8b 45 88          	mov    -0x78(%rbp),%r8d
    84eb:	8b 8d 78 ff ff ff    	mov    -0x88(%rbp),%ecx
    84f1:	4c 89 ff             	mov    %r15,%rdi
    84f4:	8b 55 80             	mov    -0x80(%rbp),%edx
    84f7:	8b b5 74 ff ff ff    	mov    -0x8c(%rbp),%esi
    84fd:	e8 00 00 00 00       	callq  8502 <l2cap_sig_channel+0x292>
    8502:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		len  -= cmd_len;
    8508:	45 29 f5             	sub    %r14d,%r13d
		data += cmd_len;
    850b:	0f b7 db             	movzwl %bx,%ebx
	while (len >= L2CAP_CMD_HDR_SIZE) {
    850e:	41 83 fd 03          	cmp    $0x3,%r13d
		data += cmd_len;
    8512:	4d 8d 0c 1c          	lea    (%r12,%rbx,1),%r9
	while (len >= L2CAP_CMD_HDR_SIZE) {
    8516:	0f 8f 7c fe ff ff    	jg     8398 <l2cap_sig_channel+0x128>
    851c:	0f 1f 40 00          	nopl   0x0(%rax)
	kfree_skb(skb);
    8520:	48 8b 7d 90          	mov    -0x70(%rbp),%rdi
    8524:	e8 00 00 00 00       	callq  8529 <l2cap_sig_channel+0x2b9>
}
    8529:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    852d:	65 48 33 04 25 28 00 	xor    %gs:0x28,%rax
    8534:	00 00 
    8536:	0f 85 42 0b 00 00    	jne    907e <l2cap_sig_channel+0xe0e>
    853c:	48 83 c4 78          	add    $0x78,%rsp
    8540:	5b                   	pop    %rbx
    8541:	41 5c                	pop    %r12
    8543:	41 5d                	pop    %r13
    8545:	41 5e                	pop    %r14
    8547:	41 5f                	pop    %r15
    8549:	5d                   	pop    %rbp
    854a:	c3                   	retq   
    854b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
	BT_DBG("conn %p", conn);
    8550:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 8557 <l2cap_sig_channel+0x2e7>
    8557:	74 1f                	je     8578 <l2cap_sig_channel+0x308>
    8559:	48 8b 55 a8          	mov    -0x58(%rbp),%rdx
    855d:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    8564:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    856b:	31 c0                	xor    %eax,%eax
    856d:	e8 00 00 00 00       	callq  8572 <l2cap_sig_channel+0x302>
    8572:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
	return l2cap_connect_rsp(conn, cmd, data);
    8578:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    857c:	48 8d 75 b0          	lea    -0x50(%rbp),%rsi
    8580:	4c 89 e2             	mov    %r12,%rdx
    8583:	e8 f8 e6 ff ff       	callq  6c80 <l2cap_connect_rsp>
    8588:	89 c6                	mov    %eax,%esi
		if (err) {
    858a:	85 f6                	test   %esi,%esi
    858c:	0f 84 76 ff ff ff    	je     8508 <l2cap_sig_channel+0x298>
			BT_ERR("Wrong link type (%d)", err);
    8592:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    8599:	31 c0                	xor    %eax,%eax
		len  -= cmd_len;
    859b:	45 29 f5             	sub    %r14d,%r13d
			BT_ERR("Wrong link type (%d)", err);
    859e:	e8 00 00 00 00       	callq  85a3 <l2cap_sig_channel+0x333>
			l2cap_send_cmd(conn, cmd.ident, L2CAP_COMMAND_REJ, sizeof(rej), &rej);
    85a3:	0f b6 75 b1          	movzbl -0x4f(%rbp),%esi
    85a7:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
			rej.reason = cpu_to_le16(L2CAP_REJ_NOT_UNDERSTOOD);
    85ab:	31 d2                	xor    %edx,%edx
			l2cap_send_cmd(conn, cmd.ident, L2CAP_COMMAND_REJ, sizeof(rej), &rej);
    85ad:	4c 8d 45 b4          	lea    -0x4c(%rbp),%r8
			rej.reason = cpu_to_le16(L2CAP_REJ_NOT_UNDERSTOOD);
    85b1:	66 89 55 b4          	mov    %dx,-0x4c(%rbp)
			l2cap_send_cmd(conn, cmd.ident, L2CAP_COMMAND_REJ, sizeof(rej), &rej);
    85b5:	b9 02 00 00 00       	mov    $0x2,%ecx
    85ba:	ba 01 00 00 00       	mov    $0x1,%edx
		data += cmd_len;
    85bf:	0f b7 db             	movzwl %bx,%ebx
			l2cap_send_cmd(conn, cmd.ident, L2CAP_COMMAND_REJ, sizeof(rej), &rej);
    85c2:	e8 f9 8d ff ff       	callq  13c0 <l2cap_send_cmd>
	while (len >= L2CAP_CMD_HDR_SIZE) {
    85c7:	41 83 fd 03          	cmp    $0x3,%r13d
		data += cmd_len;
    85cb:	4d 8d 0c 1c          	lea    (%r12,%rbx,1),%r9
	while (len >= L2CAP_CMD_HDR_SIZE) {
    85cf:	0f 8f c3 fd ff ff    	jg     8398 <l2cap_sig_channel+0x128>
    85d5:	e9 46 ff ff ff       	jmpq   8520 <l2cap_sig_channel+0x2b0>
    85da:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
	switch (cmd->code) {
    85e0:	40 80 fe 12          	cmp    $0x12,%sil
    85e4:	0f 84 16 fe ff ff    	je     8400 <l2cap_sig_channel+0x190>
    85ea:	40 80 fe 13          	cmp    $0x13,%sil
    85ee:	66 90                	xchg   %ax,%ax
    85f0:	0f 84 12 ff ff ff    	je     8508 <l2cap_sig_channel+0x298>
    85f6:	40 80 fe 01          	cmp    $0x1,%sil
    85fa:	0f 84 08 ff ff ff    	je     8508 <l2cap_sig_channel+0x298>
		BT_ERR("Unknown LE signaling command 0x%2.2x", cmd->code);
    8600:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    8607:	31 c0                	xor    %eax,%eax
    8609:	e8 00 00 00 00       	callq  860e <l2cap_sig_channel+0x39e>
		return -EINVAL;
    860e:	be ea ff ff ff       	mov    $0xffffffea,%esi
    8613:	e9 7a ff ff ff       	jmpq   8592 <l2cap_sig_channel+0x322>
    8618:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    861f:	00 
			BT_DBG("corrupted command");
    8620:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 8627 <l2cap_sig_channel+0x3b7>
    8627:	0f 84 f3 fe ff ff    	je     8520 <l2cap_sig_channel+0x2b0>
    862d:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    8634:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    863b:	31 c0                	xor    %eax,%eax
    863d:	e8 00 00 00 00       	callq  8642 <l2cap_sig_channel+0x3d2>
    8642:	e9 d9 fe ff ff       	jmpq   8520 <l2cap_sig_channel+0x2b0>
    8647:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    864e:	00 00 
		BT_ERR("Unknown BR/EDR signaling command 0x%2.2x", cmd->code);
    8650:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    8657:	31 c0                	xor    %eax,%eax
    8659:	e8 00 00 00 00       	callq  865e <l2cap_sig_channel+0x3ee>
		err = -EINVAL;
    865e:	be ea ff ff ff       	mov    $0xffffffea,%esi
    8663:	e9 2a ff ff ff       	jmpq   8592 <l2cap_sig_channel+0x322>
    8668:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    866f:	00 
	if (cmd_len != sizeof(*rsp))
    8670:	66 83 fb 02          	cmp    $0x2,%bx
    8674:	0f 85 3e 05 00 00    	jne    8bb8 <l2cap_sig_channel+0x948>
	BT_DBG("icid %d", icid);
    867a:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 8681 <l2cap_sig_channel+0x411>
	icid = le16_to_cpu(rsp->icid);
    8681:	41 0f b7 41 04       	movzwl 0x4(%r9),%eax
	BT_DBG("icid %d", icid);
    8686:	0f 84 7c fe ff ff    	je     8508 <l2cap_sig_channel+0x298>
    868c:	0f b7 d0             	movzwl %ax,%edx
    868f:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    8696:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    869d:	31 c0                	xor    %eax,%eax
    869f:	e8 00 00 00 00       	callq  86a4 <l2cap_sig_channel+0x434>
    86a4:	e9 5f fe ff ff       	jmpq   8508 <l2cap_sig_channel+0x298>
    86a9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
	if (cmd_len != sizeof(*cfm))
    86b0:	66 83 fb 04          	cmp    $0x4,%bx
    86b4:	0f 85 fe 04 00 00    	jne    8bb8 <l2cap_sig_channel+0x948>
	BT_DBG("icid %d, result %d", icid, result);
    86ba:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 86c1 <l2cap_sig_channel+0x451>
	icid = le16_to_cpu(cfm->icid);
    86c1:	45 0f b7 79 04       	movzwl 0x4(%r9),%r15d
	result = le16_to_cpu(cfm->result);
    86c6:	41 0f b7 51 06       	movzwl 0x6(%r9),%edx
	BT_DBG("icid %d, result %d", icid, result);
    86cb:	0f 85 d5 07 00 00    	jne    8ea6 <l2cap_sig_channel+0xc36>
    86d1:	89 c1                	mov    %eax,%ecx
	BT_DBG("icid %d", icid);
    86d3:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 86da <l2cap_sig_channel+0x46a>
    86da:	0f 85 ed 07 00 00    	jne    8ecd <l2cap_sig_channel+0xc5d>
	l2cap_send_cmd(conn, ident, L2CAP_MOVE_CHAN_CFM_RSP, sizeof(rsp), &rsp);
    86e0:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    86e4:	4c 8d 45 b4          	lea    -0x4c(%rbp),%r8
    86e8:	0f b6 f1             	movzbl %cl,%esi
    86eb:	ba 11 00 00 00       	mov    $0x11,%edx
    86f0:	b9 02 00 00 00       	mov    $0x2,%ecx
		len  -= cmd_len;
    86f5:	45 29 f5             	sub    %r14d,%r13d
	rsp.icid = cpu_to_le16(icid);
    86f8:	66 44 89 7d b4       	mov    %r15w,-0x4c(%rbp)
		data += cmd_len;
    86fd:	0f b7 db             	movzwl %bx,%ebx
	l2cap_send_cmd(conn, ident, L2CAP_MOVE_CHAN_CFM_RSP, sizeof(rsp), &rsp);
    8700:	e8 bb 8c ff ff       	callq  13c0 <l2cap_send_cmd>
	while (len >= L2CAP_CMD_HDR_SIZE) {
    8705:	41 83 fd 03          	cmp    $0x3,%r13d
		data += cmd_len;
    8709:	4d 8d 0c 1c          	lea    (%r12,%rbx,1),%r9
	while (len >= L2CAP_CMD_HDR_SIZE) {
    870d:	0f 8f 85 fc ff ff    	jg     8398 <l2cap_sig_channel+0x128>
    8713:	e9 08 fe ff ff       	jmpq   8520 <l2cap_sig_channel+0x2b0>
    8718:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    871f:	00 
	if (cmd_len != sizeof(*rsp))
    8720:	66 83 fb 04          	cmp    $0x4,%bx
    8724:	0f 85 8e 04 00 00    	jne    8bb8 <l2cap_sig_channel+0x948>
	BT_DBG("icid %d, result %d", icid, result);
    872a:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 8731 <l2cap_sig_channel+0x4c1>
	icid = le16_to_cpu(rsp->icid);
    8731:	45 0f b7 79 04       	movzwl 0x4(%r9),%r15d
	result = le16_to_cpu(rsp->result);
    8736:	41 0f b7 41 06       	movzwl 0x6(%r9),%eax
	BT_DBG("icid %d, result %d", icid, result);
    873b:	0f 85 b0 07 00 00    	jne    8ef1 <l2cap_sig_channel+0xc81>
	BT_DBG("icid %d, result %d", icid, result);
    8741:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 8748 <l2cap_sig_channel+0x4d8>
    8748:	0f 85 c4 07 00 00    	jne    8f12 <l2cap_sig_channel+0xca2>
	ident = l2cap_get_ident(conn);
    874e:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
		len  -= cmd_len;
    8752:	45 29 f5             	sub    %r14d,%r13d
		data += cmd_len;
    8755:	0f b7 db             	movzwl %bx,%ebx
	ident = l2cap_get_ident(conn);
    8758:	e8 53 7d ff ff       	callq  4b0 <l2cap_get_ident>
	l2cap_send_cmd(conn, ident, L2CAP_MOVE_CHAN_CFM, sizeof(cfm), &cfm);
    875d:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
	cfm.result = cpu_to_le16(result);
    8761:	b9 01 00 00 00       	mov    $0x1,%ecx
	l2cap_send_cmd(conn, ident, L2CAP_MOVE_CHAN_CFM, sizeof(cfm), &cfm);
    8766:	4c 8d 45 b4          	lea    -0x4c(%rbp),%r8
	cfm.result = cpu_to_le16(result);
    876a:	66 89 4d b6          	mov    %cx,-0x4a(%rbp)
	l2cap_send_cmd(conn, ident, L2CAP_MOVE_CHAN_CFM, sizeof(cfm), &cfm);
    876e:	0f b6 f0             	movzbl %al,%esi
    8771:	b9 04 00 00 00       	mov    $0x4,%ecx
    8776:	ba 10 00 00 00       	mov    $0x10,%edx
	cfm.icid = cpu_to_le16(icid);
    877b:	66 44 89 7d b4       	mov    %r15w,-0x4c(%rbp)
	l2cap_send_cmd(conn, ident, L2CAP_MOVE_CHAN_CFM, sizeof(cfm), &cfm);
    8780:	e8 3b 8c ff ff       	callq  13c0 <l2cap_send_cmd>
	while (len >= L2CAP_CMD_HDR_SIZE) {
    8785:	41 83 fd 03          	cmp    $0x3,%r13d
		data += cmd_len;
    8789:	4d 8d 0c 1c          	lea    (%r12,%rbx,1),%r9
	while (len >= L2CAP_CMD_HDR_SIZE) {
    878d:	0f 8f 05 fc ff ff    	jg     8398 <l2cap_sig_channel+0x128>
    8793:	e9 88 fd ff ff       	jmpq   8520 <l2cap_sig_channel+0x2b0>
    8798:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    879f:	00 
	if (cmd_len != sizeof(*req))
    87a0:	66 83 fb 03          	cmp    $0x3,%bx
    87a4:	0f 85 0e 04 00 00    	jne    8bb8 <l2cap_sig_channel+0x948>
	BT_DBG("icid %d, dest_amp_id %d", icid, req->dest_amp_id);
    87aa:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 87b1 <l2cap_sig_channel+0x541>
	icid = le16_to_cpu(req->icid);
    87b1:	45 0f b7 79 04       	movzwl 0x4(%r9),%r15d
	BT_DBG("icid %d, dest_amp_id %d", icid, req->dest_amp_id);
    87b6:	0f 85 79 07 00 00    	jne    8f35 <l2cap_sig_channel+0xcc5>
	if (!enable_hs)
    87bc:	80 3d 00 00 00 00 00 	cmpb   $0x0,0x0(%rip)        # 87c3 <l2cap_sig_channel+0x553>
    87c3:	0f 84 95 fe ff ff    	je     865e <l2cap_sig_channel+0x3ee>
	BT_DBG("icid %d, result %d", icid, result);
    87c9:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 87d0 <l2cap_sig_channel+0x560>
	l2cap_send_move_chan_rsp(conn, cmd->ident, icid, result);
    87d0:	44 0f b6 45 b1       	movzbl -0x4f(%rbp),%r8d
	BT_DBG("icid %d, result %d", icid, result);
    87d5:	0f 85 51 08 00 00    	jne    902c <l2cap_sig_channel+0xdbc>
	rsp.result = cpu_to_le16(result);
    87db:	be 06 00 00 00       	mov    $0x6,%esi
	l2cap_send_cmd(conn, ident, L2CAP_MOVE_CHAN_RSP, sizeof(rsp), &rsp);
    87e0:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    87e4:	b9 04 00 00 00       	mov    $0x4,%ecx
	rsp.result = cpu_to_le16(result);
    87e9:	66 89 75 b6          	mov    %si,-0x4a(%rbp)
	l2cap_send_cmd(conn, ident, L2CAP_MOVE_CHAN_RSP, sizeof(rsp), &rsp);
    87ed:	41 0f b6 f0          	movzbl %r8b,%esi
    87f1:	4c 8d 45 b4          	lea    -0x4c(%rbp),%r8
    87f5:	ba 0f 00 00 00       	mov    $0xf,%edx
		len  -= cmd_len;
    87fa:	45 29 f5             	sub    %r14d,%r13d
	rsp.icid = cpu_to_le16(icid);
    87fd:	66 44 89 7d b4       	mov    %r15w,-0x4c(%rbp)
		data += cmd_len;
    8802:	0f b7 db             	movzwl %bx,%ebx
	l2cap_send_cmd(conn, ident, L2CAP_MOVE_CHAN_RSP, sizeof(rsp), &rsp);
    8805:	e8 b6 8b ff ff       	callq  13c0 <l2cap_send_cmd>
	while (len >= L2CAP_CMD_HDR_SIZE) {
    880a:	41 83 fd 03          	cmp    $0x3,%r13d
		data += cmd_len;
    880e:	4d 8d 0c 1c          	lea    (%r12,%rbx,1),%r9
	while (len >= L2CAP_CMD_HDR_SIZE) {
    8812:	0f 8f 80 fb ff ff    	jg     8398 <l2cap_sig_channel+0x128>
    8818:	e9 03 fd ff ff       	jmpq   8520 <l2cap_sig_channel+0x2b0>
    881d:	0f 1f 00             	nopl   (%rax)
	if (cmd_len != sizeof(*req))
    8820:	66 83 fb 05          	cmp    $0x5,%bx
    8824:	0f 85 8e 03 00 00    	jne    8bb8 <l2cap_sig_channel+0x948>
	if (!enable_hs)
    882a:	80 3d 00 00 00 00 00 	cmpb   $0x0,0x0(%rip)        # 8831 <l2cap_sig_channel+0x5c1>
    8831:	0f 84 27 fe ff ff    	je     865e <l2cap_sig_channel+0x3ee>
	BT_DBG("psm %d, scid %d, amp_id %d", psm, scid, req->amp_id);
    8837:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 883e <l2cap_sig_channel+0x5ce>
	psm = le16_to_cpu(req->psm);
    883e:	41 0f b7 51 04       	movzwl 0x4(%r9),%edx
	scid = le16_to_cpu(req->scid);
    8843:	45 0f b7 79 06       	movzwl 0x6(%r9),%r15d
	BT_DBG("psm %d, scid %d, amp_id %d", psm, scid, req->amp_id);
    8848:	0f 85 09 08 00 00    	jne    9057 <l2cap_sig_channel+0xde7>
	rsp.dcid = 0;
    884e:	31 ff                	xor    %edi,%edi
	rsp.result = __constant_cpu_to_le16(L2CAP_CR_NO_MEM);
    8850:	41 b8 04 00 00 00    	mov    $0x4,%r8d
	rsp.status = __constant_cpu_to_le16(L2CAP_CS_NO_INFO);
    8856:	45 31 c9             	xor    %r9d,%r9d
	rsp.dcid = 0;
    8859:	66 89 7d b4          	mov    %di,-0x4c(%rbp)
	l2cap_send_cmd(conn, cmd->ident, L2CAP_CREATE_CHAN_RSP,
    885d:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    8861:	0f b6 f0             	movzbl %al,%esi
	rsp.result = __constant_cpu_to_le16(L2CAP_CR_NO_MEM);
    8864:	66 44 89 45 b8       	mov    %r8w,-0x48(%rbp)
	l2cap_send_cmd(conn, cmd->ident, L2CAP_CREATE_CHAN_RSP,
    8869:	4c 8d 45 b4          	lea    -0x4c(%rbp),%r8
    886d:	b9 08 00 00 00       	mov    $0x8,%ecx
    8872:	ba 0d 00 00 00       	mov    $0xd,%edx
		len  -= cmd_len;
    8877:	45 29 f5             	sub    %r14d,%r13d
	rsp.status = __constant_cpu_to_le16(L2CAP_CS_NO_INFO);
    887a:	66 44 89 4d ba       	mov    %r9w,-0x46(%rbp)
	rsp.scid = cpu_to_le16(scid);
    887f:	66 44 89 7d b6       	mov    %r15w,-0x4a(%rbp)
		data += cmd_len;
    8884:	0f b7 db             	movzwl %bx,%ebx
	l2cap_send_cmd(conn, cmd->ident, L2CAP_CREATE_CHAN_RSP,
    8887:	e8 34 8b ff ff       	callq  13c0 <l2cap_send_cmd>
	while (len >= L2CAP_CMD_HDR_SIZE) {
    888c:	41 83 fd 03          	cmp    $0x3,%r13d
		data += cmd_len;
    8890:	4d 8d 0c 1c          	lea    (%r12,%rbx,1),%r9
	while (len >= L2CAP_CMD_HDR_SIZE) {
    8894:	0f 8f fe fa ff ff    	jg     8398 <l2cap_sig_channel+0x128>
    889a:	e9 81 fc ff ff       	jmpq   8520 <l2cap_sig_channel+0x2b0>
    889f:	90                   	nop
	BT_DBG("type 0x%4.4x result 0x%2.2x", type, result);
    88a0:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 88a7 <l2cap_sig_channel+0x637>
	type   = __le16_to_cpu(rsp->type);
    88a7:	45 0f b7 79 04       	movzwl 0x4(%r9),%r15d
	result = __le16_to_cpu(rsp->result);
    88ac:	45 0f b7 41 06       	movzwl 0x6(%r9),%r8d
	BT_DBG("type 0x%4.4x result 0x%2.2x", type, result);
    88b1:	0f 85 f1 07 00 00    	jne    90a8 <l2cap_sig_channel+0xe38>
	if (cmd->ident != conn->info_ident ||
    88b7:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    88bb:	3a 47 2a             	cmp    0x2a(%rdi),%al
    88be:	0f 85 44 fc ff ff    	jne    8508 <l2cap_sig_channel+0x298>
    88c4:	f6 47 29 08          	testb  $0x8,0x29(%rdi)
    88c8:	0f 85 3a fc ff ff    	jne    8508 <l2cap_sig_channel+0x298>
    88ce:	48 8b bd 68 ff ff ff 	mov    -0x98(%rbp),%rdi
    88d5:	4c 89 4d 80          	mov    %r9,-0x80(%rbp)
    88d9:	44 89 45 88          	mov    %r8d,-0x78(%rbp)
    88dd:	e8 00 00 00 00       	callq  88e2 <l2cap_sig_channel+0x672>
	if (ret)
    88e2:	85 c0                	test   %eax,%eax
    88e4:	44 8b 45 88          	mov    -0x78(%rbp),%r8d
    88e8:	4c 8b 4d 80          	mov    -0x80(%rbp),%r9
    88ec:	74 09                	je     88f7 <l2cap_sig_channel+0x687>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    88ee:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    88f2:	f0 80 60 30 fe       	lock andb $0xfe,0x30(%rax)
	if (result != L2CAP_IR_SUCCESS) {
    88f7:	66 45 85 c0          	test   %r8w,%r8w
    88fb:	0f 85 9b 02 00 00    	jne    8b9c <l2cap_sig_channel+0x92c>
	switch (type) {
    8901:	66 41 83 ff 02       	cmp    $0x2,%r15w
    8906:	0f 84 20 05 00 00    	je     8e2c <l2cap_sig_channel+0xbbc>
    890c:	66 41 83 ff 03       	cmp    $0x3,%r15w
    8911:	0f 85 f1 fb ff ff    	jne    8508 <l2cap_sig_channel+0x298>
		conn->fixed_chan_mask = rsp->data[0];
    8917:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    891b:	41 0f b6 41 08       	movzbl 0x8(%r9),%eax
		conn->info_state |= L2CAP_INFO_FEAT_MASK_REQ_DONE;
    8920:	80 4f 29 08          	orb    $0x8,0x29(%rdi)
		conn->info_ident = 0;
    8924:	c6 47 2a 00          	movb   $0x0,0x2a(%rdi)
		conn->fixed_chan_mask = rsp->data[0];
    8928:	88 47 28             	mov    %al,0x28(%rdi)
		l2cap_conn_start(conn);
    892b:	e8 e0 ee ff ff       	callq  7810 <l2cap_conn_start>
    8930:	e9 d3 fb ff ff       	jmpq   8508 <l2cap_sig_channel+0x298>
    8935:	0f 1f 00             	nopl   (%rax)
	BT_DBG("type 0x%4.4x", type);
    8938:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 893f <l2cap_sig_channel+0x6cf>
	type = __le16_to_cpu(req->type);
    893f:	45 0f b7 79 04       	movzwl 0x4(%r9),%r15d
	BT_DBG("type 0x%4.4x", type);
    8944:	0f 85 0e 06 00 00    	jne    8f58 <l2cap_sig_channel+0xce8>
	if (type == L2CAP_IT_FEAT_MASK) {
    894a:	66 41 83 ff 02       	cmp    $0x2,%r15w
    894f:	0f 84 63 04 00 00    	je     8db8 <l2cap_sig_channel+0xb48>
	} else if (type == L2CAP_IT_FIXED_CHAN) {
    8955:	66 41 83 ff 03       	cmp    $0x3,%r15w
    895a:	0f 84 b0 03 00 00    	je     8d10 <l2cap_sig_channel+0xaa0>
		l2cap_send_cmd(conn, cmd->ident,
    8960:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    8964:	4c 8d 45 b4          	lea    -0x4c(%rbp),%r8
		rsp.result = cpu_to_le16(L2CAP_IR_NOTSUPP);
    8968:	41 bb 01 00 00 00    	mov    $0x1,%r11d
		l2cap_send_cmd(conn, cmd->ident,
    896e:	0f b6 f0             	movzbl %al,%esi
    8971:	b9 04 00 00 00       	mov    $0x4,%ecx
    8976:	ba 0b 00 00 00       	mov    $0xb,%edx
		len  -= cmd_len;
    897b:	45 29 f5             	sub    %r14d,%r13d
		rsp.type   = cpu_to_le16(type);
    897e:	66 44 89 7d b4       	mov    %r15w,-0x4c(%rbp)
		rsp.result = cpu_to_le16(L2CAP_IR_NOTSUPP);
    8983:	66 44 89 5d b6       	mov    %r11w,-0x4a(%rbp)
		data += cmd_len;
    8988:	0f b7 db             	movzwl %bx,%ebx
		l2cap_send_cmd(conn, cmd->ident,
    898b:	e8 30 8a ff ff       	callq  13c0 <l2cap_send_cmd>
	while (len >= L2CAP_CMD_HDR_SIZE) {
    8990:	41 83 fd 03          	cmp    $0x3,%r13d
		data += cmd_len;
    8994:	4d 8d 0c 1c          	lea    (%r12,%rbx,1),%r9
	while (len >= L2CAP_CMD_HDR_SIZE) {
    8998:	0f 8f fa f9 ff ff    	jg     8398 <l2cap_sig_channel+0x128>
    899e:	e9 7d fb ff ff       	jmpq   8520 <l2cap_sig_channel+0x2b0>
    89a3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
		l2cap_send_cmd(conn, cmd->ident, L2CAP_ECHO_RSP, cmd_len, data);
    89a8:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    89ac:	0f b6 f0             	movzbl %al,%esi
    89af:	4d 89 e0             	mov    %r12,%r8
    89b2:	44 89 f1             	mov    %r14d,%ecx
    89b5:	ba 09 00 00 00       	mov    $0x9,%edx
		len  -= cmd_len;
    89ba:	45 29 f5             	sub    %r14d,%r13d
		data += cmd_len;
    89bd:	0f b7 db             	movzwl %bx,%ebx
		l2cap_send_cmd(conn, cmd->ident, L2CAP_ECHO_RSP, cmd_len, data);
    89c0:	e8 fb 89 ff ff       	callq  13c0 <l2cap_send_cmd>
	while (len >= L2CAP_CMD_HDR_SIZE) {
    89c5:	41 83 fd 03          	cmp    $0x3,%r13d
		data += cmd_len;
    89c9:	4d 8d 0c 1c          	lea    (%r12,%rbx,1),%r9
	while (len >= L2CAP_CMD_HDR_SIZE) {
    89cd:	0f 8f c5 f9 ff ff    	jg     8398 <l2cap_sig_channel+0x128>
    89d3:	e9 48 fb ff ff       	jmpq   8520 <l2cap_sig_channel+0x2b0>
    89d8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    89df:	00 
	BT_DBG("dcid 0x%4.4x scid 0x%4.4x", dcid, scid);
    89e0:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 89e7 <l2cap_sig_channel+0x777>
	scid = __le16_to_cpu(rsp->scid);
    89e7:	45 0f b7 79 06       	movzwl 0x6(%r9),%r15d
	dcid = __le16_to_cpu(rsp->dcid);
    89ec:	41 0f b7 41 04       	movzwl 0x4(%r9),%eax
	BT_DBG("dcid 0x%4.4x scid 0x%4.4x", dcid, scid);
    89f1:	0f 85 83 05 00 00    	jne    8f7a <l2cap_sig_channel+0xd0a>
	mutex_lock(&conn->chan_lock);
    89f7:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    89fb:	e8 00 00 00 00       	callq  8a00 <l2cap_sig_channel+0x790>
	list_for_each_entry(c, &conn->chan_l, list) {
    8a00:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8a04:	48 8b 80 30 01 00 00 	mov    0x130(%rax),%rax
    8a0b:	48 39 45 98          	cmp    %rax,-0x68(%rbp)
    8a0f:	48 8d 90 e8 fc ff ff 	lea    -0x318(%rax),%rdx
    8a16:	74 39                	je     8a51 <l2cap_sig_channel+0x7e1>
		if (c->scid == cid)
    8a18:	66 44 3b b8 04 fd ff 	cmp    -0x2fc(%rax),%r15w
    8a1f:	ff 
    8a20:	48 8b 4d 98          	mov    -0x68(%rbp),%rcx
    8a24:	75 18                	jne    8a3e <l2cap_sig_channel+0x7ce>
    8a26:	e9 9d 01 00 00       	jmpq   8bc8 <l2cap_sig_channel+0x958>
    8a2b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    8a30:	66 44 3b b8 04 fd ff 	cmp    -0x2fc(%rax),%r15w
    8a37:	ff 
    8a38:	0f 84 8a 01 00 00    	je     8bc8 <l2cap_sig_channel+0x958>
	list_for_each_entry(c, &conn->chan_l, list) {
    8a3e:	48 8b 82 18 03 00 00 	mov    0x318(%rdx),%rax
    8a45:	48 39 c1             	cmp    %rax,%rcx
    8a48:	48 8d 90 e8 fc ff ff 	lea    -0x318(%rax),%rdx
    8a4f:	75 df                	jne    8a30 <l2cap_sig_channel+0x7c0>
	mutex_unlock(&conn->chan_lock);
    8a51:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    8a55:	e8 00 00 00 00       	callq  8a5a <l2cap_sig_channel+0x7ea>
		len  -= cmd_len;
    8a5a:	45 29 f5             	sub    %r14d,%r13d
		data += cmd_len;
    8a5d:	0f b7 db             	movzwl %bx,%ebx
	while (len >= L2CAP_CMD_HDR_SIZE) {
    8a60:	41 83 fd 03          	cmp    $0x3,%r13d
		data += cmd_len;
    8a64:	4d 8d 0c 1c          	lea    (%r12,%rbx,1),%r9
	while (len >= L2CAP_CMD_HDR_SIZE) {
    8a68:	0f 8f 2a f9 ff ff    	jg     8398 <l2cap_sig_channel+0x128>
    8a6e:	e9 ad fa ff ff       	jmpq   8520 <l2cap_sig_channel+0x2b0>
    8a73:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
	BT_DBG("scid 0x%4.4x dcid 0x%4.4x", scid, dcid);
    8a78:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 8a7f <l2cap_sig_channel+0x80f>
	scid = __le16_to_cpu(req->scid);
    8a7f:	41 0f b7 41 06       	movzwl 0x6(%r9),%eax
	dcid = __le16_to_cpu(req->dcid);
    8a84:	45 0f b7 41 04       	movzwl 0x4(%r9),%r8d
	BT_DBG("scid 0x%4.4x dcid 0x%4.4x", scid, dcid);
    8a89:	0f 85 0c 05 00 00    	jne    8f9b <l2cap_sig_channel+0xd2b>
	mutex_lock(&conn->chan_lock);
    8a8f:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    8a93:	44 89 45 88          	mov    %r8d,-0x78(%rbp)
    8a97:	e8 00 00 00 00       	callq  8a9c <l2cap_sig_channel+0x82c>
	list_for_each_entry(c, &conn->chan_l, list) {
    8a9c:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8aa0:	48 8b 80 30 01 00 00 	mov    0x130(%rax),%rax
    8aa7:	48 39 45 98          	cmp    %rax,-0x68(%rbp)
    8aab:	4c 8d b8 e8 fc ff ff 	lea    -0x318(%rax),%r15
    8ab2:	74 9d                	je     8a51 <l2cap_sig_channel+0x7e1>
		if (c->scid == cid)
    8ab4:	44 8b 45 88          	mov    -0x78(%rbp),%r8d
    8ab8:	66 44 3b 80 04 fd ff 	cmp    -0x2fc(%rax),%r8w
    8abf:	ff 
    8ac0:	48 8b 55 98          	mov    -0x68(%rbp),%rdx
    8ac4:	75 18                	jne    8ade <l2cap_sig_channel+0x86e>
    8ac6:	e9 75 01 00 00       	jmpq   8c40 <l2cap_sig_channel+0x9d0>
    8acb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    8ad0:	66 44 3b 80 04 fd ff 	cmp    -0x2fc(%rax),%r8w
    8ad7:	ff 
    8ad8:	0f 84 62 01 00 00    	je     8c40 <l2cap_sig_channel+0x9d0>
	list_for_each_entry(c, &conn->chan_l, list) {
    8ade:	49 8b 87 18 03 00 00 	mov    0x318(%r15),%rax
    8ae5:	48 39 c2             	cmp    %rax,%rdx
    8ae8:	4c 8d b8 e8 fc ff ff 	lea    -0x318(%rax),%r15
    8aef:	75 df                	jne    8ad0 <l2cap_sig_channel+0x860>
    8af1:	e9 5b ff ff ff       	jmpq   8a51 <l2cap_sig_channel+0x7e1>
    8af6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    8afd:	00 00 00 
		err = l2cap_config_rsp(conn, cmd, data);
    8b00:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    8b04:	48 8d 75 b0          	lea    -0x50(%rbp),%rsi
    8b08:	4c 89 e2             	mov    %r12,%rdx
    8b0b:	e8 b0 b5 ff ff       	callq  40c0 <l2cap_config_rsp>
    8b10:	89 c6                	mov    %eax,%esi
    8b12:	e9 73 fa ff ff       	jmpq   858a <l2cap_sig_channel+0x31a>
    8b17:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    8b1e:	00 00 
		err = l2cap_config_req(conn, cmd, cmd_len, data);
    8b20:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    8b24:	48 8d 75 b0          	lea    -0x50(%rbp),%rsi
    8b28:	4c 89 e1             	mov    %r12,%rcx
    8b2b:	44 89 f2             	mov    %r14d,%edx
    8b2e:	e8 0d 9c ff ff       	callq  2740 <l2cap_config_req>
    8b33:	89 c6                	mov    %eax,%esi
    8b35:	e9 50 fa ff ff       	jmpq   858a <l2cap_sig_channel+0x31a>
    8b3a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		err = l2cap_connect_req(conn, cmd, data);
    8b40:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    8b44:	48 8d 75 b0          	lea    -0x50(%rbp),%rsi
    8b48:	4c 89 e2             	mov    %r12,%rdx
    8b4b:	e8 c0 f0 ff ff       	callq  7c10 <l2cap_connect_req>
    8b50:	89 c6                	mov    %eax,%esi
    8b52:	e9 33 fa ff ff       	jmpq   858a <l2cap_sig_channel+0x31a>
    8b57:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    8b5e:	00 00 
	if (rej->reason != L2CAP_REJ_NOT_UNDERSTOOD)
    8b60:	66 41 83 79 04 00    	cmpw   $0x0,0x4(%r9)
    8b66:	0f 85 9c f9 ff ff    	jne    8508 <l2cap_sig_channel+0x298>
	if ((conn->info_state & L2CAP_INFO_FEAT_MASK_REQ_SENT) &&
    8b6c:	48 8b 4d a8          	mov    -0x58(%rbp),%rcx
    8b70:	f6 41 29 04          	testb  $0x4,0x29(%rcx)
    8b74:	0f 84 8e f9 ff ff    	je     8508 <l2cap_sig_channel+0x298>
    8b7a:	3a 41 2a             	cmp    0x2a(%rcx),%al
    8b7d:	0f 85 85 f9 ff ff    	jne    8508 <l2cap_sig_channel+0x298>
	ret = del_timer_sync(&work->timer);
    8b83:	48 8b bd 68 ff ff ff 	mov    -0x98(%rbp),%rdi
    8b8a:	e8 00 00 00 00       	callq  8b8f <l2cap_sig_channel+0x91f>
	if (ret)
    8b8f:	85 c0                	test   %eax,%eax
    8b91:	74 09                	je     8b9c <l2cap_sig_channel+0x92c>
    8b93:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8b97:	f0 80 60 30 fe       	lock andb $0xfe,0x30(%rax)
			conn->info_state |= L2CAP_INFO_FEAT_MASK_REQ_DONE;
    8b9c:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    8ba0:	80 48 29 08          	orb    $0x8,0x29(%rax)
			conn->info_ident = 0;
    8ba4:	c6 40 2a 00          	movb   $0x0,0x2a(%rax)
			l2cap_conn_start(conn);
    8ba8:	48 89 c7             	mov    %rax,%rdi
    8bab:	e8 60 ec ff ff       	callq  7810 <l2cap_conn_start>
    8bb0:	e9 53 f9 ff ff       	jmpq   8508 <l2cap_sig_channel+0x298>
    8bb5:	0f 1f 00             	nopl   (%rax)
		return -EPROTO;
    8bb8:	be b9 ff ff ff       	mov    $0xffffffb9,%esi
    8bbd:	e9 d0 f9 ff ff       	jmpq   8592 <l2cap_sig_channel+0x322>
    8bc2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
	if (!chan) {
    8bc8:	48 85 d2             	test   %rdx,%rdx
    8bcb:	0f 84 80 fe ff ff    	je     8a51 <l2cap_sig_channel+0x7e1>
	mutex_lock(&chan->lock);
    8bd1:	4c 8d ba 48 03 00 00 	lea    0x348(%rdx),%r15
    8bd8:	48 89 55 88          	mov    %rdx,-0x78(%rbp)
    8bdc:	4c 89 ff             	mov    %r15,%rdi
    8bdf:	e8 00 00 00 00       	callq  8be4 <l2cap_sig_channel+0x974>
    8be4:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
    8be8:	f0 ff 42 14          	lock incl 0x14(%rdx)
	l2cap_chan_del(chan, 0);
    8bec:	31 f6                	xor    %esi,%esi
    8bee:	48 89 d7             	mov    %rdx,%rdi
    8bf1:	e8 4a dd ff ff       	callq  6940 <l2cap_chan_del>
	mutex_unlock(&chan->lock);
    8bf6:	4c 89 ff             	mov    %r15,%rdi
    8bf9:	e8 00 00 00 00       	callq  8bfe <l2cap_sig_channel+0x98e>
	chan->ops->close(chan->data);
    8bfe:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
    8c02:	48 8b 82 40 03 00 00 	mov    0x340(%rdx),%rax
    8c09:	48 8b ba 38 03 00 00 	mov    0x338(%rdx),%rdi
    8c10:	ff 50 18             	callq  *0x18(%rax)
	asm volatile(LOCK_PREFIX "decl %0; sete %1"
    8c13:	48 8b 55 88          	mov    -0x78(%rbp),%rdx
    8c17:	f0 ff 4a 14          	lock decl 0x14(%rdx)
    8c1b:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    8c1e:	84 c0                	test   %al,%al
    8c20:	0f 84 2b fe ff ff    	je     8a51 <l2cap_sig_channel+0x7e1>
		kfree(c);
    8c26:	48 89 d7             	mov    %rdx,%rdi
    8c29:	e8 00 00 00 00       	callq  8c2e <l2cap_sig_channel+0x9be>
	mutex_unlock(&conn->chan_lock);
    8c2e:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    8c32:	e8 00 00 00 00       	callq  8c37 <l2cap_sig_channel+0x9c7>
    8c37:	e9 1e fe ff ff       	jmpq   8a5a <l2cap_sig_channel+0x7ea>
    8c3c:	0f 1f 40 00          	nopl   0x0(%rax)
	if (!chan) {
    8c40:	4d 85 ff             	test   %r15,%r15
    8c43:	0f 84 08 fe ff ff    	je     8a51 <l2cap_sig_channel+0x7e1>
	mutex_lock(&chan->lock);
    8c49:	4d 8d 8f 48 03 00 00 	lea    0x348(%r15),%r9
    8c50:	4c 89 cf             	mov    %r9,%rdi
    8c53:	4c 89 4d 80          	mov    %r9,-0x80(%rbp)
    8c57:	e8 00 00 00 00       	callq  8c5c <l2cap_sig_channel+0x9ec>
	rsp.dcid = cpu_to_le16(chan->scid);
    8c5c:	41 0f b7 57 1c       	movzwl 0x1c(%r15),%edx
	sk = chan->sk;
    8c61:	49 8b 07             	mov    (%r15),%rax
	l2cap_send_cmd(conn, cmd->ident, L2CAP_DISCONN_RSP, sizeof(rsp), &rsp);
    8c64:	4c 8d 45 b4          	lea    -0x4c(%rbp),%r8
    8c68:	0f b6 75 b1          	movzbl -0x4f(%rbp),%esi
    8c6c:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    8c70:	b9 04 00 00 00       	mov    $0x4,%ecx
	sk = chan->sk;
    8c75:	48 89 45 88          	mov    %rax,-0x78(%rbp)
	rsp.dcid = cpu_to_le16(chan->scid);
    8c79:	66 89 55 b4          	mov    %dx,-0x4c(%rbp)
	rsp.scid = cpu_to_le16(chan->dcid);
    8c7d:	41 0f b7 57 1a       	movzwl 0x1a(%r15),%edx
    8c82:	66 89 55 b6          	mov    %dx,-0x4a(%rbp)
	l2cap_send_cmd(conn, cmd->ident, L2CAP_DISCONN_RSP, sizeof(rsp), &rsp);
    8c86:	ba 07 00 00 00       	mov    $0x7,%edx
    8c8b:	e8 30 87 ff ff       	callq  13c0 <l2cap_send_cmd>
	lock_sock_nested(sk, 0);
    8c90:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    8c94:	31 f6                	xor    %esi,%esi
    8c96:	48 89 c7             	mov    %rax,%rdi
    8c99:	e8 00 00 00 00       	callq  8c9e <l2cap_sig_channel+0xa2e>
	sk->sk_shutdown = SHUTDOWN_MASK;
    8c9e:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    8ca2:	80 88 20 01 00 00 03 	orb    $0x3,0x120(%rax)
	release_sock(sk);
    8ca9:	48 89 c7             	mov    %rax,%rdi
    8cac:	e8 00 00 00 00       	callq  8cb1 <l2cap_sig_channel+0xa41>
	asm volatile(LOCK_PREFIX "incl %0"
    8cb1:	f0 41 ff 47 14       	lock incl 0x14(%r15)
	l2cap_chan_del(chan, ECONNRESET);
    8cb6:	be 68 00 00 00       	mov    $0x68,%esi
    8cbb:	4c 89 ff             	mov    %r15,%rdi
    8cbe:	e8 7d dc ff ff       	callq  6940 <l2cap_chan_del>
	mutex_unlock(&chan->lock);
    8cc3:	4c 8b 4d 80          	mov    -0x80(%rbp),%r9
    8cc7:	4c 89 cf             	mov    %r9,%rdi
    8cca:	e8 00 00 00 00       	callq  8ccf <l2cap_sig_channel+0xa5f>
	chan->ops->close(chan->data);
    8ccf:	49 8b 87 40 03 00 00 	mov    0x340(%r15),%rax
    8cd6:	49 8b bf 38 03 00 00 	mov    0x338(%r15),%rdi
    8cdd:	ff 50 18             	callq  *0x18(%rax)
	asm volatile(LOCK_PREFIX "decl %0; sete %1"
    8ce0:	f0 41 ff 4f 14       	lock decl 0x14(%r15)
    8ce5:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    8ce8:	84 c0                	test   %al,%al
    8cea:	0f 84 61 fd ff ff    	je     8a51 <l2cap_sig_channel+0x7e1>
		kfree(c);
    8cf0:	4c 89 ff             	mov    %r15,%rdi
    8cf3:	e8 00 00 00 00       	callq  8cf8 <l2cap_sig_channel+0xa88>
	mutex_unlock(&conn->chan_lock);
    8cf8:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    8cfc:	e8 00 00 00 00       	callq  8d01 <l2cap_sig_channel+0xa91>
    8d01:	e9 54 fd ff ff       	jmpq   8a5a <l2cap_sig_channel+0x7ea>
    8d06:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    8d0d:	00 00 00 
		if (enable_hs)
    8d10:	80 3d 00 00 00 00 00 	cmpb   $0x0,0x0(%rip)        # 8d17 <l2cap_sig_channel+0xaa7>
    8d17:	0f 84 03 01 00 00    	je     8e20 <l2cap_sig_channel+0xbb0>
			l2cap_fixed_chan[0] |= L2CAP_FC_A2MP;
    8d1d:	80 0d 00 00 00 00 08 	orb    $0x8,0x0(%rip)        # 8d24 <l2cap_sig_channel+0xab4>
		rsp->result = cpu_to_le16(L2CAP_IR_SUCCESS);
    8d24:	31 d2                	xor    %edx,%edx
		l2cap_send_cmd(conn, cmd->ident,
    8d26:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    8d2a:	4c 8d 45 bc          	lea    -0x44(%rbp),%r8
		rsp->result = cpu_to_le16(L2CAP_IR_SUCCESS);
    8d2e:	66 89 55 be          	mov    %dx,-0x42(%rbp)
		memcpy(rsp->data, l2cap_fixed_chan, sizeof(l2cap_fixed_chan));
    8d32:	48 8b 15 00 00 00 00 	mov    0x0(%rip),%rdx        # 8d39 <l2cap_sig_channel+0xac9>
		rsp->type   = cpu_to_le16(L2CAP_IT_FIXED_CHAN);
    8d39:	41 bf 03 00 00 00    	mov    $0x3,%r15d
		l2cap_send_cmd(conn, cmd->ident,
    8d3f:	0f b6 f0             	movzbl %al,%esi
    8d42:	b9 0c 00 00 00       	mov    $0xc,%ecx
		len  -= cmd_len;
    8d47:	45 29 f5             	sub    %r14d,%r13d
		rsp->type   = cpu_to_le16(L2CAP_IT_FIXED_CHAN);
    8d4a:	66 44 89 7d bc       	mov    %r15w,-0x44(%rbp)
		data += cmd_len;
    8d4f:	0f b7 db             	movzwl %bx,%ebx
		memcpy(rsp->data, l2cap_fixed_chan, sizeof(l2cap_fixed_chan));
    8d52:	48 89 55 c0          	mov    %rdx,-0x40(%rbp)
		l2cap_send_cmd(conn, cmd->ident,
    8d56:	ba 0b 00 00 00       	mov    $0xb,%edx
    8d5b:	e8 60 86 ff ff       	callq  13c0 <l2cap_send_cmd>
	while (len >= L2CAP_CMD_HDR_SIZE) {
    8d60:	41 83 fd 03          	cmp    $0x3,%r13d
		data += cmd_len;
    8d64:	4d 8d 0c 1c          	lea    (%r12,%rbx,1),%r9
	while (len >= L2CAP_CMD_HDR_SIZE) {
    8d68:	0f 8f 2a f6 ff ff    	jg     8398 <l2cap_sig_channel+0x128>
    8d6e:	e9 ad f7 ff ff       	jmpq   8520 <l2cap_sig_channel+0x2b0>
    8d73:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
	l2cap_send_cmd(conn, cmd->ident, L2CAP_CONN_PARAM_UPDATE_RSP,
    8d78:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    8d7c:	4c 8d 45 b4          	lea    -0x4c(%rbp),%r8
		rsp.result = cpu_to_le16(L2CAP_CONN_PARAM_REJECTED);
    8d80:	b8 01 00 00 00       	mov    $0x1,%eax
	l2cap_send_cmd(conn, cmd->ident, L2CAP_CONN_PARAM_UPDATE_RSP,
    8d85:	b9 02 00 00 00       	mov    $0x2,%ecx
    8d8a:	ba 13 00 00 00       	mov    $0x13,%edx
		len  -= cmd_len;
    8d8f:	45 29 f5             	sub    %r14d,%r13d
		rsp.result = cpu_to_le16(L2CAP_CONN_PARAM_REJECTED);
    8d92:	66 89 45 b4          	mov    %ax,-0x4c(%rbp)
		data += cmd_len;
    8d96:	0f b7 db             	movzwl %bx,%ebx
	l2cap_send_cmd(conn, cmd->ident, L2CAP_CONN_PARAM_UPDATE_RSP,
    8d99:	e8 22 86 ff ff       	callq  13c0 <l2cap_send_cmd>
	while (len >= L2CAP_CMD_HDR_SIZE) {
    8d9e:	41 83 fd 03          	cmp    $0x3,%r13d
		data += cmd_len;
    8da2:	4d 8d 0c 1c          	lea    (%r12,%rbx,1),%r9
	while (len >= L2CAP_CMD_HDR_SIZE) {
    8da6:	0f 8f ec f5 ff ff    	jg     8398 <l2cap_sig_channel+0x128>
    8dac:	e9 6f f7 ff ff       	jmpq   8520 <l2cap_sig_channel+0x2b0>
    8db1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		rsp->result = cpu_to_le16(L2CAP_IR_SUCCESS);
    8db8:	31 f6                	xor    %esi,%esi
		u32 feat_mask = l2cap_feat_mask;
    8dba:	80 3d 00 00 00 00 01 	cmpb   $0x1,0x0(%rip)        # 8dc1 <l2cap_sig_channel+0xb51>
		rsp->type   = cpu_to_le16(L2CAP_IT_FEAT_MASK);
    8dc1:	b9 02 00 00 00       	mov    $0x2,%ecx
    8dc6:	66 89 4d bc          	mov    %cx,-0x44(%rbp)
		l2cap_send_cmd(conn, cmd->ident,
    8dca:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    8dce:	4c 8d 45 bc          	lea    -0x44(%rbp),%r8
		rsp->result = cpu_to_le16(L2CAP_IR_SUCCESS);
    8dd2:	66 89 75 be          	mov    %si,-0x42(%rbp)
		l2cap_send_cmd(conn, cmd->ident,
    8dd6:	0f b6 f0             	movzbl %al,%esi
		data += cmd_len;
    8dd9:	0f b7 db             	movzwl %bx,%ebx
		u32 feat_mask = l2cap_feat_mask;
    8ddc:	19 d2                	sbb    %edx,%edx
    8dde:	83 e2 38             	and    $0x38,%edx
    8de1:	83 ea 80             	sub    $0xffffff80,%edx
			feat_mask |= L2CAP_FEAT_EXT_FLOW
    8de4:	89 d1                	mov    %edx,%ecx
    8de6:	81 c9 40 01 00 00    	or     $0x140,%ecx
    8dec:	80 3d 00 00 00 00 00 	cmpb   $0x0,0x0(%rip)        # 8df3 <l2cap_sig_channel+0xb83>
    8df3:	0f 45 d1             	cmovne %ecx,%edx
		l2cap_send_cmd(conn, cmd->ident,
    8df6:	b9 08 00 00 00       	mov    $0x8,%ecx
		len  -= cmd_len;
    8dfb:	45 29 f5             	sub    %r14d,%r13d
	*((__le32 *)p) = cpu_to_le32(val);
    8dfe:	89 55 c0             	mov    %edx,-0x40(%rbp)
		l2cap_send_cmd(conn, cmd->ident,
    8e01:	ba 0b 00 00 00       	mov    $0xb,%edx
    8e06:	e8 b5 85 ff ff       	callq  13c0 <l2cap_send_cmd>
	while (len >= L2CAP_CMD_HDR_SIZE) {
    8e0b:	41 83 fd 03          	cmp    $0x3,%r13d
		data += cmd_len;
    8e0f:	4d 8d 0c 1c          	lea    (%r12,%rbx,1),%r9
	while (len >= L2CAP_CMD_HDR_SIZE) {
    8e13:	0f 8f 7f f5 ff ff    	jg     8398 <l2cap_sig_channel+0x128>
    8e19:	e9 02 f7 ff ff       	jmpq   8520 <l2cap_sig_channel+0x2b0>
    8e1e:	66 90                	xchg   %ax,%ax
			l2cap_fixed_chan[0] &= ~L2CAP_FC_A2MP;
    8e20:	80 25 00 00 00 00 f7 	andb   $0xf7,0x0(%rip)        # 8e27 <l2cap_sig_channel+0xbb7>
    8e27:	e9 f8 fe ff ff       	jmpq   8d24 <l2cap_sig_channel+0xab4>
static inline u32 get_unaligned_le32(const void *p)
    8e2c:	41 8b 41 08          	mov    0x8(%r9),%eax
		conn->feat_mask = get_unaligned_le32(rsp->data);
    8e30:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
		if (conn->feat_mask & L2CAP_FEAT_FIXED_CHAN) {
    8e34:	a8 80                	test   $0x80,%al
		conn->feat_mask = get_unaligned_le32(rsp->data);
    8e36:	89 47 24             	mov    %eax,0x24(%rdi)
		if (conn->feat_mask & L2CAP_FEAT_FIXED_CHAN) {
    8e39:	0f 84 5d fd ff ff    	je     8b9c <l2cap_sig_channel+0x92c>
			req.type = cpu_to_le16(L2CAP_IT_FIXED_CHAN);
    8e3f:	41 ba 03 00 00 00    	mov    $0x3,%r10d
			conn->info_ident = l2cap_get_ident(conn);
    8e45:	49 89 ff             	mov    %rdi,%r15
			req.type = cpu_to_le16(L2CAP_IT_FIXED_CHAN);
    8e48:	66 44 89 55 b4       	mov    %r10w,-0x4c(%rbp)
			conn->info_ident = l2cap_get_ident(conn);
    8e4d:	e8 5e 76 ff ff       	callq  4b0 <l2cap_get_ident>
			l2cap_send_cmd(conn, conn->info_ident,
    8e52:	4c 8d 45 b4          	lea    -0x4c(%rbp),%r8
			conn->info_ident = l2cap_get_ident(conn);
    8e56:	4c 89 ff             	mov    %r15,%rdi
    8e59:	41 88 47 2a          	mov    %al,0x2a(%r15)
			l2cap_send_cmd(conn, conn->info_ident,
    8e5d:	0f b6 f0             	movzbl %al,%esi
    8e60:	b9 02 00 00 00       	mov    $0x2,%ecx
    8e65:	ba 0a 00 00 00       	mov    $0xa,%edx
    8e6a:	e8 51 85 ff ff       	callq  13c0 <l2cap_send_cmd>
    8e6f:	e9 94 f6 ff ff       	jmpq   8508 <l2cap_sig_channel+0x298>
		BT_DBG("code 0x%2.2x len %d id 0x%2.2x", cmd.code, cmd_len, cmd.ident);
    8e74:	0f b6 55 b0          	movzbl -0x50(%rbp),%edx
    8e78:	44 0f b6 45 b1       	movzbl -0x4f(%rbp),%r8d
    8e7d:	44 0f b7 f3          	movzwl %bx,%r14d
    8e81:	44 89 f1             	mov    %r14d,%ecx
    8e84:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    8e8b:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    8e92:	31 c0                	xor    %eax,%eax
    8e94:	4c 89 4d 88          	mov    %r9,-0x78(%rbp)
    8e98:	e8 00 00 00 00       	callq  8e9d <l2cap_sig_channel+0xc2d>
    8e9d:	4c 8b 4d 88          	mov    -0x78(%rbp),%r9
    8ea1:	e9 14 f5 ff ff       	jmpq   83ba <l2cap_sig_channel+0x14a>
	BT_DBG("icid %d, result %d", icid, result);
    8ea6:	41 0f b7 c7          	movzwl %r15w,%eax
    8eaa:	0f b7 ca             	movzwl %dx,%ecx
    8ead:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    8eb4:	89 c2                	mov    %eax,%edx
    8eb6:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    8ebd:	31 c0                	xor    %eax,%eax
    8ebf:	e8 00 00 00 00       	callq  8ec4 <l2cap_sig_channel+0xc54>
    8ec4:	0f b6 4d b1          	movzbl -0x4f(%rbp),%ecx
    8ec8:	e9 06 f8 ff ff       	jmpq   86d3 <l2cap_sig_channel+0x463>
	BT_DBG("icid %d", icid);
    8ecd:	41 0f b7 d7          	movzwl %r15w,%edx
    8ed1:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    8ed8:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    8edf:	31 c0                	xor    %eax,%eax
    8ee1:	89 4d 88             	mov    %ecx,-0x78(%rbp)
    8ee4:	e8 00 00 00 00       	callq  8ee9 <l2cap_sig_channel+0xc79>
    8ee9:	8b 4d 88             	mov    -0x78(%rbp),%ecx
    8eec:	e9 ef f7 ff ff       	jmpq   86e0 <l2cap_sig_channel+0x470>
	BT_DBG("icid %d, result %d", icid, result);
    8ef1:	0f b7 c8             	movzwl %ax,%ecx
    8ef4:	41 0f b7 d7          	movzwl %r15w,%edx
    8ef8:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    8eff:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    8f06:	31 c0                	xor    %eax,%eax
    8f08:	e8 00 00 00 00       	callq  8f0d <l2cap_sig_channel+0xc9d>
    8f0d:	e9 2f f8 ff ff       	jmpq   8741 <l2cap_sig_channel+0x4d1>
	BT_DBG("icid %d, result %d", icid, result);
    8f12:	41 0f b7 d7          	movzwl %r15w,%edx
    8f16:	b9 01 00 00 00       	mov    $0x1,%ecx
    8f1b:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    8f22:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    8f29:	31 c0                	xor    %eax,%eax
    8f2b:	e8 00 00 00 00       	callq  8f30 <l2cap_sig_channel+0xcc0>
    8f30:	e9 19 f8 ff ff       	jmpq   874e <l2cap_sig_channel+0x4de>
	BT_DBG("icid %d, dest_amp_id %d", icid, req->dest_amp_id);
    8f35:	41 0f b6 49 06       	movzbl 0x6(%r9),%ecx
    8f3a:	41 0f b7 d7          	movzwl %r15w,%edx
    8f3e:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    8f45:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    8f4c:	31 c0                	xor    %eax,%eax
    8f4e:	e8 00 00 00 00       	callq  8f53 <l2cap_sig_channel+0xce3>
    8f53:	e9 64 f8 ff ff       	jmpq   87bc <l2cap_sig_channel+0x54c>
	BT_DBG("type 0x%4.4x", type);
    8f58:	41 0f b7 d7          	movzwl %r15w,%edx
    8f5c:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    8f63:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    8f6a:	31 c0                	xor    %eax,%eax
    8f6c:	e8 00 00 00 00       	callq  8f71 <l2cap_sig_channel+0xd01>
    8f71:	0f b6 45 b1          	movzbl -0x4f(%rbp),%eax
    8f75:	e9 d0 f9 ff ff       	jmpq   894a <l2cap_sig_channel+0x6da>
	BT_DBG("dcid 0x%4.4x scid 0x%4.4x", dcid, scid);
    8f7a:	0f b7 d0             	movzwl %ax,%edx
    8f7d:	41 0f b7 cf          	movzwl %r15w,%ecx
    8f81:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    8f88:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    8f8f:	31 c0                	xor    %eax,%eax
    8f91:	e8 00 00 00 00       	callq  8f96 <l2cap_sig_channel+0xd26>
    8f96:	e9 5c fa ff ff       	jmpq   89f7 <l2cap_sig_channel+0x787>
	BT_DBG("scid 0x%4.4x dcid 0x%4.4x", scid, dcid);
    8f9b:	41 0f b7 c8          	movzwl %r8w,%ecx
    8f9f:	0f b7 d0             	movzwl %ax,%edx
    8fa2:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    8fa9:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    8fb0:	31 c0                	xor    %eax,%eax
    8fb2:	44 89 45 88          	mov    %r8d,-0x78(%rbp)
    8fb6:	e8 00 00 00 00       	callq  8fbb <l2cap_sig_channel+0xd4b>
    8fbb:	44 8b 45 88          	mov    -0x78(%rbp),%r8d
    8fbf:	e9 cb fa ff ff       	jmpq   8a8f <l2cap_sig_channel+0x81f>
	BT_DBG("min 0x%4.4x max 0x%4.4x latency: 0x%4.4x Timeout: 0x%4.4x",
    8fc4:	0f b7 85 7e ff ff ff 	movzwl -0x82(%rbp),%eax
    8fcb:	0f b7 bd 7c ff ff ff 	movzwl -0x84(%rbp),%edi
    8fd2:	41 0f b7 ca          	movzwl %r10w,%ecx
    8fd6:	41 0f b7 d3          	movzwl %r11w,%edx
    8fda:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    8fe1:	44 89 95 64 ff ff ff 	mov    %r10d,-0x9c(%rbp)
    8fe8:	44 89 9d 70 ff ff ff 	mov    %r11d,-0x90(%rbp)
    8fef:	89 4d 80             	mov    %ecx,-0x80(%rbp)
    8ff2:	89 95 74 ff ff ff    	mov    %edx,-0x8c(%rbp)
    8ff8:	89 45 88             	mov    %eax,-0x78(%rbp)
    8ffb:	89 bd 78 ff ff ff    	mov    %edi,-0x88(%rbp)
    9001:	41 89 c1             	mov    %eax,%r9d
    9004:	41 89 f8             	mov    %edi,%r8d
    9007:	31 c0                	xor    %eax,%eax
    9009:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    9010:	e8 00 00 00 00       	callq  9015 <l2cap_sig_channel+0xda5>
    9015:	0f b6 75 b1          	movzbl -0x4f(%rbp),%esi
    9019:	44 8b 95 64 ff ff ff 	mov    -0x9c(%rbp),%r10d
    9020:	44 8b 9d 70 ff ff ff 	mov    -0x90(%rbp),%r11d
    9027:	e9 36 f4 ff ff       	jmpq   8462 <l2cap_sig_channel+0x1f2>
	BT_DBG("icid %d, result %d", icid, result);
    902c:	41 0f b7 d7          	movzwl %r15w,%edx
    9030:	b9 06 00 00 00       	mov    $0x6,%ecx
    9035:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    903c:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    9043:	31 c0                	xor    %eax,%eax
    9045:	44 89 45 88          	mov    %r8d,-0x78(%rbp)
    9049:	e8 00 00 00 00       	callq  904e <l2cap_sig_channel+0xdde>
    904e:	44 8b 45 88          	mov    -0x78(%rbp),%r8d
    9052:	e9 84 f7 ff ff       	jmpq   87db <l2cap_sig_channel+0x56b>
	BT_DBG("psm %d, scid %d, amp_id %d", psm, scid, req->amp_id);
    9057:	45 0f b6 41 08       	movzbl 0x8(%r9),%r8d
    905c:	41 0f b7 cf          	movzwl %r15w,%ecx
    9060:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    9067:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    906e:	31 c0                	xor    %eax,%eax
    9070:	e8 00 00 00 00       	callq  9075 <l2cap_sig_channel+0xe05>
    9075:	0f b6 45 b1          	movzbl -0x4f(%rbp),%eax
    9079:	e9 d0 f7 ff ff       	jmpq   884e <l2cap_sig_channel+0x5de>
}
    907e:	e8 00 00 00 00       	callq  9083 <l2cap_sig_channel+0xe13>
	BT_DBG("conn %p", conn);
    9083:	4c 89 f2             	mov    %r14,%rdx
    9086:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    908d:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    9094:	31 c0                	xor    %eax,%eax
    9096:	4c 89 4d a8          	mov    %r9,-0x58(%rbp)
    909a:	e8 00 00 00 00       	callq  909f <l2cap_sig_channel+0xe2f>
    909f:	4c 8b 4d a8          	mov    -0x58(%rbp),%r9
    90a3:	e9 07 f2 ff ff       	jmpq   82af <l2cap_sig_channel+0x3f>
	BT_DBG("type 0x%4.4x result 0x%2.2x", type, result);
    90a8:	41 0f b7 c8          	movzwl %r8w,%ecx
    90ac:	41 0f b7 d7          	movzwl %r15w,%edx
    90b0:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    90b7:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    90be:	31 c0                	xor    %eax,%eax
    90c0:	4c 89 4d 80          	mov    %r9,-0x80(%rbp)
    90c4:	44 89 45 88          	mov    %r8d,-0x78(%rbp)
    90c8:	e8 00 00 00 00       	callq  90cd <l2cap_sig_channel+0xe5d>
    90cd:	0f b6 45 b1          	movzbl -0x4f(%rbp),%eax
    90d1:	44 8b 45 88          	mov    -0x78(%rbp),%r8d
    90d5:	4c 8b 4d 80          	mov    -0x80(%rbp),%r9
    90d9:	e9 d9 f7 ff ff       	jmpq   88b7 <l2cap_sig_channel+0x647>
    90de:	66 90                	xchg   %ax,%ax

00000000000090e0 <l2cap_recv_frame>:
{
    90e0:	55                   	push   %rbp
    90e1:	48 89 e5             	mov    %rsp,%rbp
    90e4:	41 56                	push   %r14
    90e6:	41 55                	push   %r13
    90e8:	41 54                	push   %r12
    90ea:	53                   	push   %rbx
    90eb:	e8 00 00 00 00       	callq  90f0 <l2cap_recv_frame+0x10>
	struct l2cap_hdr *lh = (void *) skb->data;
    90f0:	4c 8b a6 e0 00 00 00 	mov    0xe0(%rsi),%r12
{
    90f7:	48 89 f3             	mov    %rsi,%rbx
    90fa:	49 89 fe             	mov    %rdi,%r14
	skb_pull(skb, L2CAP_HDR_SIZE);
    90fd:	be 04 00 00 00       	mov    $0x4,%esi
    9102:	48 89 df             	mov    %rbx,%rdi
    9105:	e8 00 00 00 00       	callq  910a <l2cap_recv_frame+0x2a>
	if (len != skb->len) {
    910a:	41 0f b7 14 24       	movzwl (%r12),%edx
	cid = __le16_to_cpu(lh->cid);
    910f:	45 0f b7 6c 24 02    	movzwl 0x2(%r12),%r13d
	if (len != skb->len) {
    9115:	3b 53 68             	cmp    0x68(%rbx),%edx
    9118:	75 4e                	jne    9168 <l2cap_recv_frame+0x88>
	BT_DBG("len %d, cid 0x%4.4x", len, cid);
    911a:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 9121 <l2cap_recv_frame+0x41>
    9121:	0f 85 b7 03 00 00    	jne    94de <l2cap_recv_frame+0x3fe>
	switch (cid) {
    9127:	66 41 83 fd 06       	cmp    $0x6,%r13w
    912c:	0f 87 5e 01 00 00    	ja     9290 <l2cap_recv_frame+0x1b0>
    9132:	41 0f b7 c5          	movzwl %r13w,%eax
    9136:	ff 24 c5 00 00 00 00 	jmpq   *0x0(,%rax,8)
    913d:	0f 1f 00             	nopl   (%rax)
		BT_DBG("unknown cid 0x%4.4x", cid);
    9140:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 9147 <l2cap_recv_frame+0x67>
    9147:	74 1f                	je     9168 <l2cap_recv_frame+0x88>
    9149:	44 89 ea             	mov    %r13d,%edx
    914c:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    9153:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    915a:	31 c0                	xor    %eax,%eax
    915c:	e8 00 00 00 00       	callq  9161 <l2cap_recv_frame+0x81>
    9161:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
	kfree_skb(skb);
    9168:	48 89 df             	mov    %rbx,%rdi
    916b:	e8 00 00 00 00       	callq  9170 <l2cap_recv_frame+0x90>
}
    9170:	5b                   	pop    %rbx
    9171:	41 5c                	pop    %r12
    9173:	41 5d                	pop    %r13
    9175:	41 5e                	pop    %r14
    9177:	5d                   	pop    %rbp
    9178:	c3                   	retq   
    9179:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		if (smp_sig_channel(conn, skb))
    9180:	48 89 de             	mov    %rbx,%rsi
    9183:	4c 89 f7             	mov    %r14,%rdi
    9186:	e8 00 00 00 00       	callq  918b <l2cap_recv_frame+0xab>
    918b:	85 c0                	test   %eax,%eax
    918d:	74 e1                	je     9170 <l2cap_recv_frame+0x90>
			l2cap_conn_del(conn->hcon, EACCES);
    918f:	49 8b 3e             	mov    (%r14),%rdi
    9192:	be 0d 00 00 00       	mov    $0xd,%esi
    9197:	e8 64 dd ff ff       	callq  6f00 <l2cap_conn_del>
    919c:	eb d2                	jmp    9170 <l2cap_recv_frame+0x90>
    919e:	66 90                	xchg   %ax,%ax
		l2cap_sig_channel(conn, skb);
    91a0:	48 89 de             	mov    %rbx,%rsi
    91a3:	4c 89 f7             	mov    %r14,%rdi
    91a6:	e8 c5 f0 ff ff       	callq  8270 <l2cap_sig_channel>
}
    91ab:	5b                   	pop    %rbx
    91ac:	41 5c                	pop    %r12
    91ae:	41 5d                	pop    %r13
    91b0:	41 5e                	pop    %r14
    91b2:	5d                   	pop    %rbp
    91b3:	c3                   	retq   
    91b4:	0f 1f 40 00          	nopl   0x0(%rax)
static inline u16 get_unaligned_le16(const void *p)
    91b8:	48 8b 83 e0 00 00 00 	mov    0xe0(%rbx),%rax
		skb_pull(skb, 2);
    91bf:	be 02 00 00 00       	mov    $0x2,%esi
    91c4:	48 89 df             	mov    %rbx,%rdi
    91c7:	44 0f b7 20          	movzwl (%rax),%r12d
    91cb:	e8 00 00 00 00       	callq  91d0 <l2cap_recv_frame+0xf0>
	chan = l2cap_global_chan_by_psm(0, psm, conn->src, conn->dst);
    91d0:	49 8b 4e 10          	mov    0x10(%r14),%rcx
    91d4:	49 8b 56 18          	mov    0x18(%r14),%rdx
    91d8:	31 ff                	xor    %edi,%edi
    91da:	44 89 e6             	mov    %r12d,%esi
    91dd:	e8 3e 77 ff ff       	callq  920 <l2cap_global_chan_by_psm>
	if (!chan)
    91e2:	48 85 c0             	test   %rax,%rax
	chan = l2cap_global_chan_by_psm(0, psm, conn->src, conn->dst);
    91e5:	49 89 c4             	mov    %rax,%r12
	if (!chan)
    91e8:	0f 84 7a ff ff ff    	je     9168 <l2cap_recv_frame+0x88>
	BT_DBG("chan %p, len %d", chan, skb->len);
    91ee:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 91f5 <l2cap_recv_frame+0x115>
    91f5:	0f 85 01 03 00 00    	jne    94fc <l2cap_recv_frame+0x41c>
	if (chan->state != BT_BOUND && chan->state != BT_CONNECTED)
    91fb:	41 0f b6 4c 24 10    	movzbl 0x10(%r12),%ecx
    9201:	83 e1 fd             	and    $0xfffffffd,%ecx
    9204:	80 f9 01             	cmp    $0x1,%cl
    9207:	0f 85 5b ff ff ff    	jne    9168 <l2cap_recv_frame+0x88>
	if (chan->imtu < skb->len)
    920d:	41 0f b7 44 24 1e    	movzwl 0x1e(%r12),%eax
    9213:	3b 43 68             	cmp    0x68(%rbx),%eax
    9216:	0f 82 4c ff ff ff    	jb     9168 <l2cap_recv_frame+0x88>
	if (!chan->ops->recv(chan->data, skb))
    921c:	49 8b 84 24 40 03 00 	mov    0x340(%r12),%rax
    9223:	00 
    9224:	49 8b bc 24 38 03 00 	mov    0x338(%r12),%rdi
    922b:	00 
    922c:	48 89 de             	mov    %rbx,%rsi
    922f:	ff 50 10             	callq  *0x10(%rax)
    9232:	85 c0                	test   %eax,%eax
    9234:	0f 85 2e ff ff ff    	jne    9168 <l2cap_recv_frame+0x88>
    923a:	e9 31 ff ff ff       	jmpq   9170 <l2cap_recv_frame+0x90>
    923f:	90                   	nop
	chan = l2cap_global_chan_by_scid(0, cid, conn->src, conn->dst);
    9240:	49 8b 4e 10          	mov    0x10(%r14),%rcx
    9244:	49 8b 56 18          	mov    0x18(%r14),%rdx
    9248:	31 ff                	xor    %edi,%edi
    924a:	be 04 00 00 00       	mov    $0x4,%esi
    924f:	e8 1c 75 ff ff       	callq  770 <l2cap_global_chan_by_scid>
	if (!chan)
    9254:	48 85 c0             	test   %rax,%rax
	chan = l2cap_global_chan_by_scid(0, cid, conn->src, conn->dst);
    9257:	49 89 c4             	mov    %rax,%r12
	if (!chan)
    925a:	0f 84 08 ff ff ff    	je     9168 <l2cap_recv_frame+0x88>
	BT_DBG("chan %p, len %d", chan, skb->len);
    9260:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 9267 <l2cap_recv_frame+0x187>
    9267:	74 92                	je     91fb <l2cap_recv_frame+0x11b>
    9269:	8b 4b 68             	mov    0x68(%rbx),%ecx
    926c:	48 89 c2             	mov    %rax,%rdx
    926f:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    9276:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    927d:	31 c0                	xor    %eax,%eax
    927f:	e8 00 00 00 00       	callq  9284 <l2cap_recv_frame+0x1a4>
    9284:	e9 72 ff ff ff       	jmpq   91fb <l2cap_recv_frame+0x11b>
    9289:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
	chan = l2cap_get_chan_by_scid(conn, cid);
    9290:	44 89 ee             	mov    %r13d,%esi
    9293:	4c 89 f7             	mov    %r14,%rdi
    9296:	e8 f5 6e ff ff       	callq  190 <l2cap_get_chan_by_scid>
	if (!chan) {
    929b:	48 85 c0             	test   %rax,%rax
	chan = l2cap_get_chan_by_scid(conn, cid);
    929e:	49 89 c4             	mov    %rax,%r12
	if (!chan) {
    92a1:	0f 84 99 fe ff ff    	je     9140 <l2cap_recv_frame+0x60>
	BT_DBG("chan %p, len %d", chan, skb->len);
    92a7:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 92ae <l2cap_recv_frame+0x1ce>
    92ae:	0f 85 68 02 00 00    	jne    951c <l2cap_recv_frame+0x43c>
	if (chan->state != BT_CONNECTED)
    92b4:	41 80 7c 24 10 01    	cmpb   $0x1,0x10(%r12)
    92ba:	74 24                	je     92e0 <l2cap_recv_frame+0x200>
	kfree_skb(skb);
    92bc:	48 89 df             	mov    %rbx,%rdi
    92bf:	e8 00 00 00 00       	callq  92c4 <l2cap_recv_frame+0x1e4>
	mutex_unlock(&chan->lock);
    92c4:	49 8d bc 24 48 03 00 	lea    0x348(%r12),%rdi
    92cb:	00 
    92cc:	e8 00 00 00 00       	callq  92d1 <l2cap_recv_frame+0x1f1>
}
    92d1:	5b                   	pop    %rbx
    92d2:	41 5c                	pop    %r12
    92d4:	41 5d                	pop    %r13
    92d6:	41 5e                	pop    %r14
    92d8:	5d                   	pop    %rbp
    92d9:	c3                   	retq   
    92da:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
	switch (chan->mode) {
    92e0:	41 0f b6 44 24 24    	movzbl 0x24(%r12),%eax
    92e6:	3c 03                	cmp    $0x3,%al
    92e8:	0f 84 ba 01 00 00    	je     94a8 <l2cap_recv_frame+0x3c8>
    92ee:	3c 04                	cmp    $0x4,%al
    92f0:	74 5e                	je     9350 <l2cap_recv_frame+0x270>
    92f2:	84 c0                	test   %al,%al
    92f4:	74 2a                	je     9320 <l2cap_recv_frame+0x240>
		BT_DBG("chan %p: bad mode 0x%2.2x", chan, chan->mode);
    92f6:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 92fd <l2cap_recv_frame+0x21d>
    92fd:	74 bd                	je     92bc <l2cap_recv_frame+0x1dc>
    92ff:	0f b6 c8             	movzbl %al,%ecx
    9302:	4c 89 e2             	mov    %r12,%rdx
    9305:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    930c:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    9313:	31 c0                	xor    %eax,%eax
    9315:	e8 00 00 00 00       	callq  931a <l2cap_recv_frame+0x23a>
    931a:	eb a0                	jmp    92bc <l2cap_recv_frame+0x1dc>
    931c:	0f 1f 40 00          	nopl   0x0(%rax)
		if (chan->imtu < skb->len)
    9320:	41 0f b7 44 24 1e    	movzwl 0x1e(%r12),%eax
    9326:	3b 43 68             	cmp    0x68(%rbx),%eax
    9329:	72 91                	jb     92bc <l2cap_recv_frame+0x1dc>
		if (!chan->ops->recv(chan->data, skb))
    932b:	49 8b 84 24 40 03 00 	mov    0x340(%r12),%rax
    9332:	00 
    9333:	49 8b bc 24 38 03 00 	mov    0x338(%r12),%rdi
    933a:	00 
    933b:	48 89 de             	mov    %rbx,%rsi
    933e:	ff 50 10             	callq  *0x10(%rax)
    9341:	85 c0                	test   %eax,%eax
    9343:	0f 85 73 ff ff ff    	jne    92bc <l2cap_recv_frame+0x1dc>
    9349:	e9 76 ff ff ff       	jmpq   92c4 <l2cap_recv_frame+0x1e4>
    934e:	66 90                	xchg   %ax,%ax
		(addr[nr / BITS_PER_LONG])) != 0;
    9350:	49 8b 94 24 90 00 00 	mov    0x90(%r12),%rdx
    9357:	00 
		control = __get_control(chan, skb->data);
    9358:	48 8b 83 e0 00 00 00 	mov    0xe0(%rbx),%rax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    935f:	83 e2 10             	and    $0x10,%edx
    9362:	0f 84 50 01 00 00    	je     94b8 <l2cap_recv_frame+0x3d8>
static inline u32 get_unaligned_le32(const void *p)
    9368:	44 8b 28             	mov    (%rax),%r13d
    936b:	49 8b 84 24 90 00 00 	mov    0x90(%r12),%rax
    9372:	00 
		skb_pull(skb, __ctrl_size(chan));
    9373:	48 89 df             	mov    %rbx,%rdi
    9376:	48 c1 e8 04          	shr    $0x4,%rax
    937a:	83 e0 01             	and    $0x1,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    937d:	48 83 f8 01          	cmp    $0x1,%rax
    9381:	19 f6                	sbb    %esi,%esi
    9383:	83 e6 fe             	and    $0xfffffffe,%esi
    9386:	83 c6 04             	add    $0x4,%esi
    9389:	e8 00 00 00 00       	callq  938e <l2cap_recv_frame+0x2ae>
		if (l2cap_check_fcs(chan, skb))
    938e:	48 89 de             	mov    %rbx,%rsi
    9391:	4c 89 e7             	mov    %r12,%rdi
		len = skb->len;
    9394:	44 8b 73 68          	mov    0x68(%rbx),%r14d
		if (l2cap_check_fcs(chan, skb))
    9398:	e8 33 77 ff ff       	callq  ad0 <l2cap_check_fcs>
    939d:	85 c0                	test   %eax,%eax
    939f:	0f 85 17 ff ff ff    	jne    92bc <l2cap_recv_frame+0x1dc>
    93a5:	49 8b 84 24 90 00 00 	mov    0x90(%r12),%rax
    93ac:	00 
		return (ctrl & L2CAP_EXT_CTRL_SAR) >> L2CAP_EXT_CTRL_SAR_SHIFT;
    93ad:	44 89 ea             	mov    %r13d,%edx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    93b0:	a8 10                	test   $0x10,%al
    93b2:	0f 84 09 01 00 00    	je     94c1 <l2cap_recv_frame+0x3e1>
		return (ctrl & L2CAP_EXT_CTRL_SAR) >> L2CAP_EXT_CTRL_SAR_SHIFT;
    93b8:	81 e2 00 00 03 00    	and    $0x30000,%edx
    93be:	c1 ea 10             	shr    $0x10,%edx
			len -= L2CAP_SDULEN_SIZE;
    93c1:	41 8d 46 fe          	lea    -0x2(%r14),%eax
    93c5:	80 fa 01             	cmp    $0x1,%dl
    93c8:	41 0f 45 c6          	cmovne %r14d,%eax
			len -= L2CAP_FCS_SIZE;
    93cc:	41 80 7c 24 6f 01    	cmpb   $0x1,0x6f(%r12)
    93d2:	8d 50 fe             	lea    -0x2(%rax),%edx
    93d5:	0f 44 c2             	cmove  %edx,%eax
		if (len > chan->mps || len < 0 || __is_sframe(chan, control))
    93d8:	41 0f b7 54 24 7a    	movzwl 0x7a(%r12),%edx
    93de:	39 c2                	cmp    %eax,%edx
    93e0:	0f 8c d6 fe ff ff    	jl     92bc <l2cap_recv_frame+0x1dc>
    93e6:	85 c0                	test   %eax,%eax
    93e8:	0f 88 ce fe ff ff    	js     92bc <l2cap_recv_frame+0x1dc>
    93ee:	49 8b 84 24 90 00 00 	mov    0x90(%r12),%rax
    93f5:	00 
		return ctrl & L2CAP_CTRL_FRAME_TYPE;
    93f6:	44 89 e8             	mov    %r13d,%eax
    93f9:	83 e0 01             	and    $0x1,%eax
    93fc:	84 c0                	test   %al,%al
    93fe:	0f 85 b8 fe ff ff    	jne    92bc <l2cap_recv_frame+0x1dc>
    9404:	49 8b 84 24 90 00 00 	mov    0x90(%r12),%rax
    940b:	00 
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    940c:	a8 10                	test   $0x10,%al
    940e:	0f 84 bb 00 00 00    	je     94cf <l2cap_recv_frame+0x3ef>
		return (ctrl & L2CAP_EXT_CTRL_TXSEQ) >>
    9414:	44 89 e8             	mov    %r13d,%eax
    9417:	c1 e8 12             	shr    $0x12,%eax
    941a:	41 89 c6             	mov    %eax,%r14d
		if (chan->expected_tx_seq != tx_seq) {
    941d:	66 45 39 b4 24 9c 00 	cmp    %r14w,0x9c(%r12)
    9424:	00 00 
    9426:	74 30                	je     9458 <l2cap_recv_frame+0x378>
			kfree_skb(chan->sdu);
    9428:	49 8b bc 24 b8 00 00 	mov    0xb8(%r12),%rdi
    942f:	00 
    9430:	e8 00 00 00 00       	callq  9435 <l2cap_recv_frame+0x355>
			chan->sdu = NULL;
    9435:	49 c7 84 24 b8 00 00 	movq   $0x0,0xb8(%r12)
    943c:	00 00 00 00 00 
			chan->sdu_last_frag = NULL;
    9441:	49 c7 84 24 c0 00 00 	movq   $0x0,0xc0(%r12)
    9448:	00 00 00 00 00 
			chan->sdu_len = 0;
    944d:	66 41 c7 84 24 b0 00 	movw   $0x0,0xb0(%r12)
    9454:	00 00 00 00 
	return (seq + 1) % (chan->tx_win_max + 1);
    9458:	41 0f b7 4c 24 72    	movzwl 0x72(%r12),%ecx
    945e:	41 0f b7 c6          	movzwl %r14w,%eax
		if (l2cap_reassemble_sdu(chan, skb, control) == -EMSGSIZE)
    9462:	48 89 de             	mov    %rbx,%rsi
    9465:	83 c0 01             	add    $0x1,%eax
    9468:	4c 89 e7             	mov    %r12,%rdi
    946b:	99                   	cltd   
    946c:	83 c1 01             	add    $0x1,%ecx
    946f:	f7 f9                	idiv   %ecx
    9471:	66 41 89 94 24 9c 00 	mov    %dx,0x9c(%r12)
    9478:	00 00 
    947a:	44 89 ea             	mov    %r13d,%edx
    947d:	e8 9e 7c ff ff       	callq  1120 <l2cap_reassemble_sdu>
    9482:	83 f8 a6             	cmp    $0xffffffa6,%eax
    9485:	0f 85 39 fe ff ff    	jne    92c4 <l2cap_recv_frame+0x1e4>
			l2cap_send_disconn_req(chan->conn, chan, ECONNRESET);
    948b:	49 8b 7c 24 08       	mov    0x8(%r12),%rdi
    9490:	ba 68 00 00 00       	mov    $0x68,%edx
    9495:	4c 89 e6             	mov    %r12,%rsi
    9498:	e8 63 91 ff ff       	callq  2600 <l2cap_send_disconn_req>
    949d:	e9 22 fe ff ff       	jmpq   92c4 <l2cap_recv_frame+0x1e4>
    94a2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		l2cap_ertm_data_rcv(chan, skb);
    94a8:	48 89 de             	mov    %rbx,%rsi
    94ab:	4c 89 e7             	mov    %r12,%rdi
    94ae:	e8 ed c6 ff ff       	callq  5ba0 <l2cap_ertm_data_rcv>
    94b3:	e9 0c fe ff ff       	jmpq   92c4 <l2cap_recv_frame+0x1e4>
		return get_unaligned_le16(p);
    94b8:	44 0f b7 28          	movzwl (%rax),%r13d
    94bc:	e9 aa fe ff ff       	jmpq   936b <l2cap_recv_frame+0x28b>
		return (ctrl & L2CAP_CTRL_SAR) >> L2CAP_CTRL_SAR_SHIFT;
    94c1:	81 e2 00 c0 00 00    	and    $0xc000,%edx
    94c7:	c1 ea 0e             	shr    $0xe,%edx
    94ca:	e9 f2 fe ff ff       	jmpq   93c1 <l2cap_recv_frame+0x2e1>
		return (ctrl & L2CAP_CTRL_TXSEQ) >> L2CAP_CTRL_TXSEQ_SHIFT;
    94cf:	45 89 ee             	mov    %r13d,%r14d
    94d2:	41 83 e6 7e          	and    $0x7e,%r14d
    94d6:	41 d1 ee             	shr    %r14d
    94d9:	e9 3f ff ff ff       	jmpq   941d <l2cap_recv_frame+0x33d>
	BT_DBG("len %d, cid 0x%4.4x", len, cid);
    94de:	41 0f b7 cd          	movzwl %r13w,%ecx
    94e2:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    94e9:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    94f0:	31 c0                	xor    %eax,%eax
    94f2:	e8 00 00 00 00       	callq  94f7 <l2cap_recv_frame+0x417>
    94f7:	e9 2b fc ff ff       	jmpq   9127 <l2cap_recv_frame+0x47>
	BT_DBG("chan %p, len %d", chan, skb->len);
    94fc:	8b 4b 68             	mov    0x68(%rbx),%ecx
    94ff:	48 89 c2             	mov    %rax,%rdx
    9502:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    9509:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    9510:	31 c0                	xor    %eax,%eax
    9512:	e8 00 00 00 00       	callq  9517 <l2cap_recv_frame+0x437>
    9517:	e9 df fc ff ff       	jmpq   91fb <l2cap_recv_frame+0x11b>
	BT_DBG("chan %p, len %d", chan, skb->len);
    951c:	8b 4b 68             	mov    0x68(%rbx),%ecx
    951f:	48 89 c2             	mov    %rax,%rdx
    9522:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    9529:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    9530:	31 c0                	xor    %eax,%eax
    9532:	e8 00 00 00 00       	callq  9537 <l2cap_recv_frame+0x457>
    9537:	e9 78 fd ff ff       	jmpq   92b4 <l2cap_recv_frame+0x1d4>
    953c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000009540 <l2cap_chan_connect>:
{
    9540:	55                   	push   %rbp
    9541:	48 89 e5             	mov    %rsp,%rbp
    9544:	41 57                	push   %r15
    9546:	41 56                	push   %r14
    9548:	41 55                	push   %r13
    954a:	41 54                	push   %r12
    954c:	53                   	push   %rbx
    954d:	48 83 ec 38          	sub    $0x38,%rsp
    9551:	e8 00 00 00 00       	callq  9556 <l2cap_chan_connect+0x16>
	struct sock *sk = chan->sk;
    9556:	4c 8b 2f             	mov    (%rdi),%r13
	BT_DBG("%s -> %s (type %u) psm 0x%2.2x", batostr(src), batostr(dst),
    9559:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 9560 <l2cap_chan_connect+0x20>
{
    9560:	48 89 fb             	mov    %rdi,%rbx
    9563:	89 75 c8             	mov    %esi,-0x38(%rbp)
    9566:	89 55 b8             	mov    %edx,-0x48(%rbp)
    9569:	48 89 4d c0          	mov    %rcx,-0x40(%rbp)
    956d:	44 89 45 ac          	mov    %r8d,-0x54(%rbp)
	bdaddr_t *src = &bt_sk(sk)->src;
    9571:	49 8d 85 88 02 00 00 	lea    0x288(%r13),%rax
    9578:	48 89 45 b0          	mov    %rax,-0x50(%rbp)
	BT_DBG("%s -> %s (type %u) psm 0x%2.2x", batostr(src), batostr(dst),
    957c:	0f 85 75 05 00 00    	jne    9af7 <l2cap_chan_connect+0x5b7>
	hdev = hci_get_route(dst, src);
    9582:	48 8b 75 b0          	mov    -0x50(%rbp),%rsi
    9586:	48 8b 7d c0          	mov    -0x40(%rbp),%rdi
    958a:	e8 00 00 00 00       	callq  958f <l2cap_chan_connect+0x4f>
	if (!hdev)
    958f:	48 85 c0             	test   %rax,%rax
	hdev = hci_get_route(dst, src);
    9592:	49 89 c4             	mov    %rax,%r12
	if (!hdev)
    9595:	0f 84 36 04 00 00    	je     99d1 <l2cap_chan_connect+0x491>
	hci_dev_lock(hdev);
    959b:	4c 8d 78 10          	lea    0x10(%rax),%r15
	mutex_lock(&chan->lock);
    959f:	4c 8d b3 48 03 00 00 	lea    0x348(%rbx),%r14
    95a6:	4c 89 ff             	mov    %r15,%rdi
    95a9:	e8 00 00 00 00       	callq  95ae <l2cap_chan_connect+0x6e>
    95ae:	4c 89 f7             	mov    %r14,%rdi
    95b1:	e8 00 00 00 00       	callq  95b6 <l2cap_chan_connect+0x76>
	if ((__le16_to_cpu(psm) & 0x0101) != 0x0001 && !cid &&
    95b6:	0f b7 45 c8          	movzwl -0x38(%rbp),%eax
    95ba:	66 25 01 01          	and    $0x101,%ax
    95be:	66 83 f8 01          	cmp    $0x1,%ax
    95c2:	74 4c                	je     9610 <l2cap_chan_connect+0xd0>
    95c4:	66 83 7d b8 00       	cmpw   $0x0,-0x48(%rbp)
    95c9:	75 45                	jne    9610 <l2cap_chan_connect+0xd0>
    95cb:	80 7b 25 01          	cmpb   $0x1,0x25(%rbx)
		err = -EINVAL;
    95cf:	b8 ea ff ff ff       	mov    $0xffffffea,%eax
	if ((__le16_to_cpu(psm) & 0x0101) != 0x0001 && !cid &&
    95d4:	74 40                	je     9616 <l2cap_chan_connect+0xd6>
	mutex_unlock(&chan->lock);
    95d6:	4c 89 f7             	mov    %r14,%rdi
    95d9:	89 45 c8             	mov    %eax,-0x38(%rbp)
    95dc:	e8 00 00 00 00       	callq  95e1 <l2cap_chan_connect+0xa1>
	hci_dev_unlock(hdev);
    95e1:	4c 89 ff             	mov    %r15,%rdi
    95e4:	e8 00 00 00 00       	callq  95e9 <l2cap_chan_connect+0xa9>
}

/* ----- HCI Devices ----- */
static inline void hci_dev_put(struct hci_dev *d)
{
	put_device(&d->dev);
    95e9:	49 8d bc 24 38 07 00 	lea    0x738(%r12),%rdi
    95f0:	00 
    95f1:	e8 00 00 00 00       	callq  95f6 <l2cap_chan_connect+0xb6>
	return err;
    95f6:	8b 45 c8             	mov    -0x38(%rbp),%eax
}
    95f9:	48 83 c4 38          	add    $0x38,%rsp
    95fd:	5b                   	pop    %rbx
    95fe:	41 5c                	pop    %r12
    9600:	41 5d                	pop    %r13
    9602:	41 5e                	pop    %r14
    9604:	41 5f                	pop    %r15
    9606:	5d                   	pop    %rbp
    9607:	c3                   	retq   
    9608:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    960f:	00 
	if (chan->chan_type == L2CAP_CHAN_CONN_ORIENTED && !(psm || cid)) {
    9610:	80 7b 25 03          	cmpb   $0x3,0x25(%rbx)
    9614:	74 42                	je     9658 <l2cap_chan_connect+0x118>
	switch (chan->mode) {
    9616:	0f b6 43 24          	movzbl 0x24(%rbx),%eax
    961a:	84 c0                	test   %al,%al
    961c:	74 16                	je     9634 <l2cap_chan_connect+0xf4>
    961e:	8d 50 fd             	lea    -0x3(%rax),%edx
		err = -ENOTSUPP;
    9621:	b8 f4 fd ff ff       	mov    $0xfffffdf4,%eax
	switch (chan->mode) {
    9626:	80 fa 01             	cmp    $0x1,%dl
    9629:	77 ab                	ja     95d6 <l2cap_chan_connect+0x96>
		if (!disable_ertm)
    962b:	80 3d 00 00 00 00 00 	cmpb   $0x0,0x0(%rip)        # 9632 <l2cap_chan_connect+0xf2>
    9632:	75 a2                	jne    95d6 <l2cap_chan_connect+0x96>
    9634:	31 f6                	xor    %esi,%esi
    9636:	4c 89 ef             	mov    %r13,%rdi
    9639:	e8 00 00 00 00       	callq  963e <l2cap_chan_connect+0xfe>
	switch (sk->sk_state) {
    963e:	41 0f b6 45 0e       	movzbl 0xe(%r13),%eax
    9643:	3c 07                	cmp    $0x7,%al
    9645:	0f 87 cd 01 00 00    	ja     9818 <l2cap_chan_connect+0x2d8>
    964b:	ff 24 c5 00 00 00 00 	jmpq   *0x0(,%rax,8)
    9652:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
	if (chan->chan_type == L2CAP_CHAN_CONN_ORIENTED && !(psm || cid)) {
    9658:	0f b7 4d b8          	movzwl -0x48(%rbp),%ecx
		err = -EINVAL;
    965c:	b8 ea ff ff ff       	mov    $0xffffffea,%eax
	if (chan->chan_type == L2CAP_CHAN_CONN_ORIENTED && !(psm || cid)) {
    9661:	66 0b 4d c8          	or     -0x38(%rbp),%cx
    9665:	0f 84 6b ff ff ff    	je     95d6 <l2cap_chan_connect+0x96>
	switch (chan->mode) {
    966b:	0f b6 43 24          	movzbl 0x24(%rbx),%eax
    966f:	84 c0                	test   %al,%al
    9671:	75 ab                	jne    961e <l2cap_chan_connect+0xde>
    9673:	eb bf                	jmp    9634 <l2cap_chan_connect+0xf4>
    9675:	0f 1f 00             	nopl   (%rax)
		release_sock(sk);
    9678:	4c 89 ef             	mov    %r13,%rdi
    967b:	e8 00 00 00 00       	callq  9680 <l2cap_chan_connect+0x140>
		err = 0;
    9680:	31 c0                	xor    %eax,%eax
		goto done;
    9682:	e9 4f ff ff ff       	jmpq   95d6 <l2cap_chan_connect+0x96>
    9687:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    968e:	00 00 
	memcpy(dst, src, sizeof(bdaddr_t));
    9690:	48 8b 4d c0          	mov    -0x40(%rbp),%rcx
	release_sock(sk);
    9694:	4c 89 ef             	mov    %r13,%rdi
    9697:	8b 01                	mov    (%rcx),%eax
    9699:	41 89 85 8e 02 00 00 	mov    %eax,0x28e(%r13)
    96a0:	0f b7 41 04          	movzwl 0x4(%rcx),%eax
    96a4:	66 41 89 85 92 02 00 	mov    %ax,0x292(%r13)
    96ab:	00 
    96ac:	e8 00 00 00 00       	callq  96b1 <l2cap_chan_connect+0x171>
	chan->psm = psm;
    96b1:	0f b7 45 c8          	movzwl -0x38(%rbp),%eax
	if (chan->chan_type == L2CAP_CHAN_RAW) {
    96b5:	80 7b 25 01          	cmpb   $0x1,0x25(%rbx)
		switch (chan->sec_level) {
    96b9:	44 0f b6 43 2a       	movzbl 0x2a(%rbx),%r8d
	chan->psm = psm;
    96be:	66 89 43 18          	mov    %ax,0x18(%rbx)
	chan->dcid = cid;
    96c2:	0f b7 45 b8          	movzwl -0x48(%rbp),%eax
    96c6:	66 89 43 1a          	mov    %ax,0x1a(%rbx)
	if (chan->chan_type == L2CAP_CHAN_RAW) {
    96ca:	0f 84 d8 02 00 00    	je     99a8 <l2cap_chan_connect+0x468>
	} else if (chan->psm == cpu_to_le16(0x0001)) {
    96d0:	66 83 7d c8 01       	cmpw   $0x1,-0x38(%rbp)
    96d5:	0f 84 4f 01 00 00    	je     982a <l2cap_chan_connect+0x2ea>
		switch (chan->sec_level) {
    96db:	41 80 f8 02          	cmp    $0x2,%r8b
    96df:	0f 84 f6 02 00 00    	je     99db <l2cap_chan_connect+0x49b>
    96e5:	41 80 f8 03          	cmp    $0x3,%r8b
    96e9:	0f 85 99 02 00 00    	jne    9988 <l2cap_chan_connect+0x448>
    96ef:	41 b8 03 00 00 00    	mov    $0x3,%r8d
    96f5:	41 b9 05 00 00 00    	mov    $0x5,%r9d
    96fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
	if (chan->dcid == L2CAP_CID_LE_DATA)
    9700:	66 83 7d b8 04       	cmpw   $0x4,-0x48(%rbp)
		hcon = hci_connect(hdev, LE_LINK, dst, dst_type,
    9705:	0f b6 4d ac          	movzbl -0x54(%rbp),%ecx
    9709:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
	if (chan->dcid == L2CAP_CID_LE_DATA)
    970d:	0f 84 7d 02 00 00    	je     9990 <l2cap_chan_connect+0x450>
		hcon = hci_connect(hdev, ACL_LINK, dst, dst_type,
    9713:	be 01 00 00 00       	mov    $0x1,%esi
    9718:	4c 89 e7             	mov    %r12,%rdi
    971b:	e8 00 00 00 00       	callq  9720 <l2cap_chan_connect+0x1e0>
    9720:	49 89 c1             	mov    %rax,%r9
	if (IS_ERR(hcon)) {
    9723:	49 81 f9 00 f0 ff ff 	cmp    $0xfffffffffffff000,%r9
    972a:	0f 87 6f 04 00 00    	ja     9b9f <l2cap_chan_connect+0x65f>
	if (conn || status)
    9730:	49 8b 81 20 04 00 00 	mov    0x420(%r9),%rax
    9737:	48 85 c0             	test   %rax,%rax
    973a:	0f 84 bd 02 00 00    	je     99fd <l2cap_chan_connect+0x4bd>
	if (hcon->type == LE_LINK) {
    9740:	41 80 79 21 80       	cmpb   $0x80,0x21(%r9)
    9745:	0f 85 fd 00 00 00    	jne    9848 <l2cap_chan_connect+0x308>
		if (!list_empty(&conn->chan_l)) {
    974b:	48 8d 90 30 01 00 00 	lea    0x130(%rax),%rdx
    9752:	48 39 90 30 01 00 00 	cmp    %rdx,0x130(%rax)
    9759:	0f 84 e9 00 00 00    	je     9848 <l2cap_chan_connect+0x308>
    975f:	f0 41 ff 49 10       	lock decl 0x10(%r9)
    9764:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&conn->refcnt)) {
    9767:	84 c0                	test   %al,%al
    9769:	0f 84 83 00 00 00    	je     97f2 <l2cap_chan_connect+0x2b2>
		if (conn->type == ACL_LINK || conn->type == LE_LINK) {
    976f:	41 0f b6 41 21       	movzbl 0x21(%r9),%eax
    9774:	3c 80                	cmp    $0x80,%al
    9776:	74 04                	je     977c <l2cap_chan_connect+0x23c>
    9778:	3c 01                	cmp    $0x1,%al
    977a:	75 20                	jne    979c <l2cap_chan_connect+0x25c>
			del_timer(&conn->idle_timer);
    977c:	49 8d b9 f0 00 00 00 	lea    0xf0(%r9),%rdi
    9783:	4c 89 4d c8          	mov    %r9,-0x38(%rbp)
    9787:	e8 00 00 00 00       	callq  978c <l2cap_chan_connect+0x24c>
			if (conn->state == BT_CONNECTED) {
    978c:	4c 8b 4d c8          	mov    -0x38(%rbp),%r9
    9790:	66 41 83 79 1e 01    	cmpw   $0x1,0x1e(%r9)
    9796:	0f 84 2b 03 00 00    	je     9ac7 <l2cap_chan_connect+0x587>
			timeo = msecs_to_jiffies(10);
    979c:	bf 0a 00 00 00       	mov    $0xa,%edi
    97a1:	4c 89 4d c8          	mov    %r9,-0x38(%rbp)
    97a5:	e8 00 00 00 00       	callq  97aa <l2cap_chan_connect+0x26a>
    97aa:	4c 8b 4d c8          	mov    -0x38(%rbp),%r9
    97ae:	48 89 c3             	mov    %rax,%rbx
	ret = del_timer_sync(&work->timer);
    97b1:	49 8d b9 a0 00 00 00 	lea    0xa0(%r9),%rdi
		cancel_delayed_work(&conn->disc_work);
    97b8:	4d 8d a9 80 00 00 00 	lea    0x80(%r9),%r13
    97bf:	4c 89 4d c8          	mov    %r9,-0x38(%rbp)
    97c3:	e8 00 00 00 00       	callq  97c8 <l2cap_chan_connect+0x288>
	if (ret)
    97c8:	85 c0                	test   %eax,%eax
    97ca:	4c 8b 4d c8          	mov    -0x38(%rbp),%r9
    97ce:	74 09                	je     97d9 <l2cap_chan_connect+0x299>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    97d0:	f0 41 80 a1 80 00 00 	lock andb $0xfe,0x80(%r9)
    97d7:	00 fe 
		queue_delayed_work(conn->hdev->workqueue,
    97d9:	49 8b 81 18 04 00 00 	mov    0x418(%r9),%rax
    97e0:	48 89 da             	mov    %rbx,%rdx
    97e3:	4c 89 ee             	mov    %r13,%rsi
    97e6:	48 8b b8 38 03 00 00 	mov    0x338(%rax),%rdi
    97ed:	e8 00 00 00 00       	callq  97f2 <l2cap_chan_connect+0x2b2>
		err = -ENOMEM;
    97f2:	b8 f0 ff ff ff       	mov    $0xfffffff0,%eax
    97f7:	e9 da fd ff ff       	jmpq   95d6 <l2cap_chan_connect+0x96>
    97fc:	0f 1f 40 00          	nopl   0x0(%rax)
		release_sock(sk);
    9800:	4c 89 ef             	mov    %r13,%rdi
    9803:	e8 00 00 00 00       	callq  9808 <l2cap_chan_connect+0x2c8>
		err = -EISCONN;
    9808:	b8 96 ff ff ff       	mov    $0xffffff96,%eax
		goto done;
    980d:	e9 c4 fd ff ff       	jmpq   95d6 <l2cap_chan_connect+0x96>
    9812:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		release_sock(sk);
    9818:	4c 89 ef             	mov    %r13,%rdi
    981b:	e8 00 00 00 00       	callq  9820 <l2cap_chan_connect+0x2e0>
		err = -EBADFD;
    9820:	b8 b3 ff ff ff       	mov    $0xffffffb3,%eax
		goto done;
    9825:	e9 ac fd ff ff       	jmpq   95d6 <l2cap_chan_connect+0x96>
		if (chan->sec_level == BT_SECURITY_LOW)
    982a:	41 80 f8 01          	cmp    $0x1,%r8b
    982e:	0f 84 47 01 00 00    	je     997b <l2cap_chan_connect+0x43b>
    9834:	45 31 c9             	xor    %r9d,%r9d
    9837:	41 80 f8 03          	cmp    $0x3,%r8b
    983b:	41 0f 94 c1          	sete   %r9b
    983f:	e9 bc fe ff ff       	jmpq   9700 <l2cap_chan_connect+0x1c0>
    9844:	0f 1f 40 00          	nopl   0x0(%rax)
    9848:	48 8b 50 18          	mov    0x18(%rax),%rdx
    984c:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    9850:	4c 89 f7             	mov    %r14,%rdi
    9853:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    9857:	4c 89 4d b8          	mov    %r9,-0x48(%rbp)
    985b:	8b 0a                	mov    (%rdx),%ecx
    985d:	41 89 8d 88 02 00 00 	mov    %ecx,0x288(%r13)
    9864:	0f b7 52 04          	movzwl 0x4(%rdx),%edx
    9868:	66 89 50 04          	mov    %dx,0x4(%rax)
    986c:	e8 00 00 00 00       	callq  9871 <l2cap_chan_connect+0x331>
	mutex_lock(&conn->chan_lock);
    9871:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
    9875:	48 8d 90 40 01 00 00 	lea    0x140(%rax),%rdx
    987c:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    9880:	48 89 d7             	mov    %rdx,%rdi
    9883:	48 89 55 c8          	mov    %rdx,-0x38(%rbp)
    9887:	e8 00 00 00 00       	callq  988c <l2cap_chan_connect+0x34c>
	__l2cap_chan_add(conn, chan);
    988c:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
    9890:	48 89 de             	mov    %rbx,%rsi
    9893:	48 89 c7             	mov    %rax,%rdi
    9896:	e8 45 6a ff ff       	callq  2e0 <__l2cap_chan_add>
	mutex_unlock(&conn->chan_lock);
    989b:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
    989f:	48 89 d7             	mov    %rdx,%rdi
    98a2:	e8 00 00 00 00       	callq  98a7 <l2cap_chan_connect+0x367>
	mutex_lock(&chan->lock);
    98a7:	4c 89 f7             	mov    %r14,%rdi
    98aa:	e8 00 00 00 00       	callq  98af <l2cap_chan_connect+0x36f>
	l2cap_state_change(chan, BT_CONNECT);
    98af:	be 05 00 00 00       	mov    $0x5,%esi
    98b4:	48 89 df             	mov    %rbx,%rdi
    98b7:	e8 64 6e ff ff       	callq  720 <l2cap_state_change>
	__set_chan_timer(chan, sk->sk_sndtimeo);
    98bc:	49 8b 85 a8 01 00 00 	mov    0x1a8(%r13),%rax
	BT_DBG("chan %p state %s timeout %ld", chan,
    98c3:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 98ca <l2cap_chan_connect+0x38a>
    98ca:	4c 8b 4d b8          	mov    -0x48(%rbp),%r9
    98ce:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    98d2:	48 8d 83 f0 00 00 00 	lea    0xf0(%rbx),%rax
    98d9:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    98dd:	0f 85 78 02 00 00    	jne    9b5b <l2cap_chan_connect+0x61b>
	ret = del_timer_sync(&work->timer);
    98e3:	4c 8d ab 10 01 00 00 	lea    0x110(%rbx),%r13
    98ea:	4c 89 4d b8          	mov    %r9,-0x48(%rbp)
    98ee:	4c 89 ef             	mov    %r13,%rdi
    98f1:	e8 00 00 00 00       	callq  98f6 <l2cap_chan_connect+0x3b6>
	if (ret)
    98f6:	85 c0                	test   %eax,%eax
    98f8:	4c 8b 4d b8          	mov    -0x48(%rbp),%r9
    98fc:	0f 84 c6 00 00 00    	je     99c8 <l2cap_chan_connect+0x488>
    9902:	f0 80 a3 f0 00 00 00 	lock andb $0xfe,0xf0(%rbx)
    9909:	fe 
	schedule_delayed_work(work, timeout);
    990a:	48 8b 75 c8          	mov    -0x38(%rbp),%rsi
    990e:	48 8b 7d c0          	mov    -0x40(%rbp),%rdi
    9912:	4c 89 4d b8          	mov    %r9,-0x48(%rbp)
    9916:	e8 00 00 00 00       	callq  991b <l2cap_chan_connect+0x3db>
	if (hcon->state == BT_CONNECTED) {
    991b:	4c 8b 4d b8          	mov    -0x48(%rbp),%r9
    991f:	66 41 83 79 1e 01    	cmpw   $0x1,0x1e(%r9)
    9925:	74 07                	je     992e <l2cap_chan_connect+0x3ee>
	err = 0;
    9927:	31 c0                	xor    %eax,%eax
    9929:	e9 a8 fc ff ff       	jmpq   95d6 <l2cap_chan_connect+0x96>
		if (chan->chan_type != L2CAP_CHAN_CONN_ORIENTED) {
    992e:	80 7b 25 03          	cmpb   $0x3,0x25(%rbx)
    9932:	0f 84 80 01 00 00    	je     9ab8 <l2cap_chan_connect+0x578>
	ret = del_timer_sync(&work->timer);
    9938:	4c 89 ef             	mov    %r13,%rdi
    993b:	e8 00 00 00 00       	callq  9940 <l2cap_chan_connect+0x400>
	if (ret)
    9940:	85 c0                	test   %eax,%eax
    9942:	74 17                	je     995b <l2cap_chan_connect+0x41b>
    9944:	f0 80 a3 f0 00 00 00 	lock andb $0xfe,0xf0(%rbx)
    994b:	fe 
    994c:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    9950:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    9953:	84 c0                	test   %al,%al
    9955:	0f 85 8f 01 00 00    	jne    9aea <l2cap_chan_connect+0x5aa>
			if (l2cap_chan_check_security(chan))
    995b:	48 89 df             	mov    %rbx,%rdi
    995e:	e8 00 00 00 00       	callq  9963 <l2cap_chan_connect+0x423>
    9963:	85 c0                	test   %eax,%eax
    9965:	74 c0                	je     9927 <l2cap_chan_connect+0x3e7>
				l2cap_state_change(chan, BT_CONNECTED);
    9967:	be 01 00 00 00       	mov    $0x1,%esi
    996c:	48 89 df             	mov    %rbx,%rdi
    996f:	e8 ac 6d ff ff       	callq  720 <l2cap_state_change>
	err = 0;
    9974:	31 c0                	xor    %eax,%eax
    9976:	e9 5b fc ff ff       	jmpq   95d6 <l2cap_chan_connect+0x96>
			chan->sec_level = BT_SECURITY_SDP;
    997b:	c6 43 2a 00          	movb   $0x0,0x2a(%rbx)
    997f:	45 31 c0             	xor    %r8d,%r8d
    9982:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    9988:	45 31 c9             	xor    %r9d,%r9d
    998b:	e9 70 fd ff ff       	jmpq   9700 <l2cap_chan_connect+0x1c0>
		hcon = hci_connect(hdev, LE_LINK, dst, dst_type,
    9990:	be 80 00 00 00       	mov    $0x80,%esi
    9995:	4c 89 e7             	mov    %r12,%rdi
    9998:	e8 00 00 00 00       	callq  999d <l2cap_chan_connect+0x45d>
    999d:	49 89 c1             	mov    %rax,%r9
    99a0:	e9 7e fd ff ff       	jmpq   9723 <l2cap_chan_connect+0x1e3>
    99a5:	0f 1f 00             	nopl   (%rax)
		switch (chan->sec_level) {
    99a8:	41 80 f8 02          	cmp    $0x2,%r8b
    99ac:	74 3e                	je     99ec <l2cap_chan_connect+0x4ac>
    99ae:	41 80 f8 03          	cmp    $0x3,%r8b
    99b2:	75 d4                	jne    9988 <l2cap_chan_connect+0x448>
    99b4:	41 b8 03 00 00 00    	mov    $0x3,%r8d
    99ba:	41 b9 03 00 00 00    	mov    $0x3,%r9d
    99c0:	e9 3b fd ff ff       	jmpq   9700 <l2cap_chan_connect+0x1c0>
    99c5:	0f 1f 00             	nopl   (%rax)
	asm volatile(LOCK_PREFIX "incl %0"
    99c8:	f0 ff 43 14          	lock incl 0x14(%rbx)
    99cc:	e9 39 ff ff ff       	jmpq   990a <l2cap_chan_connect+0x3ca>
		return -EHOSTUNREACH;
    99d1:	b8 8f ff ff ff       	mov    $0xffffff8f,%eax
    99d6:	e9 1e fc ff ff       	jmpq   95f9 <l2cap_chan_connect+0xb9>
    99db:	41 b8 02 00 00 00    	mov    $0x2,%r8d
    99e1:	41 b9 04 00 00 00    	mov    $0x4,%r9d
    99e7:	e9 14 fd ff ff       	jmpq   9700 <l2cap_chan_connect+0x1c0>
    99ec:	41 b8 02 00 00 00    	mov    $0x2,%r8d
    99f2:	41 b9 02 00 00 00    	mov    $0x2,%r9d
    99f8:	e9 03 fd ff ff       	jmpq   9700 <l2cap_chan_connect+0x1c0>
    99fd:	4c 89 cf             	mov    %r9,%rdi
    9a00:	4c 89 4d c8          	mov    %r9,-0x38(%rbp)
    9a04:	e8 37 75 ff ff       	callq  f40 <l2cap_conn_add.part.29>
	if (!conn) {
    9a09:	48 85 c0             	test   %rax,%rax
    9a0c:	4c 8b 4d c8          	mov    -0x38(%rbp),%r9
    9a10:	0f 85 2a fd ff ff    	jne    9740 <l2cap_chan_connect+0x200>
	asm volatile(LOCK_PREFIX "decl %0; sete %1"
    9a16:	f0 41 ff 49 10       	lock decl 0x10(%r9)
    9a1b:	0f 94 c2             	sete   %dl
	if (atomic_dec_and_test(&conn->refcnt)) {
    9a1e:	84 d2                	test   %dl,%dl
		err = -ENOMEM;
    9a20:	b8 f4 ff ff ff       	mov    $0xfffffff4,%eax
    9a25:	0f 84 ab fb ff ff    	je     95d6 <l2cap_chan_connect+0x96>
		if (conn->type == ACL_LINK || conn->type == LE_LINK) {
    9a2b:	41 0f b6 41 21       	movzbl 0x21(%r9),%eax
    9a30:	3c 80                	cmp    $0x80,%al
    9a32:	74 04                	je     9a38 <l2cap_chan_connect+0x4f8>
    9a34:	3c 01                	cmp    $0x1,%al
    9a36:	75 20                	jne    9a58 <l2cap_chan_connect+0x518>
			del_timer(&conn->idle_timer);
    9a38:	49 8d b9 f0 00 00 00 	lea    0xf0(%r9),%rdi
    9a3f:	4c 89 4d c8          	mov    %r9,-0x38(%rbp)
    9a43:	e8 00 00 00 00       	callq  9a48 <l2cap_chan_connect+0x508>
			if (conn->state == BT_CONNECTED) {
    9a48:	4c 8b 4d c8          	mov    -0x38(%rbp),%r9
    9a4c:	66 41 83 79 1e 01    	cmpw   $0x1,0x1e(%r9)
    9a52:	0f 84 e0 00 00 00    	je     9b38 <l2cap_chan_connect+0x5f8>
			timeo = msecs_to_jiffies(10);
    9a58:	bf 0a 00 00 00       	mov    $0xa,%edi
    9a5d:	4c 89 4d c8          	mov    %r9,-0x38(%rbp)
    9a61:	e8 00 00 00 00       	callq  9a66 <l2cap_chan_connect+0x526>
    9a66:	4c 8b 4d c8          	mov    -0x38(%rbp),%r9
    9a6a:	48 89 c3             	mov    %rax,%rbx
	ret = del_timer_sync(&work->timer);
    9a6d:	49 8d b9 a0 00 00 00 	lea    0xa0(%r9),%rdi
		cancel_delayed_work(&conn->disc_work);
    9a74:	4d 8d a9 80 00 00 00 	lea    0x80(%r9),%r13
    9a7b:	4c 89 4d c8          	mov    %r9,-0x38(%rbp)
    9a7f:	e8 00 00 00 00       	callq  9a84 <l2cap_chan_connect+0x544>
	if (ret)
    9a84:	85 c0                	test   %eax,%eax
    9a86:	4c 8b 4d c8          	mov    -0x38(%rbp),%r9
    9a8a:	74 09                	je     9a95 <l2cap_chan_connect+0x555>
    9a8c:	f0 41 80 a1 80 00 00 	lock andb $0xfe,0x80(%r9)
    9a93:	00 fe 
		queue_delayed_work(conn->hdev->workqueue,
    9a95:	49 8b 81 18 04 00 00 	mov    0x418(%r9),%rax
    9a9c:	48 89 da             	mov    %rbx,%rdx
    9a9f:	4c 89 ee             	mov    %r13,%rsi
    9aa2:	48 8b b8 38 03 00 00 	mov    0x338(%rax),%rdi
    9aa9:	e8 00 00 00 00       	callq  9aae <l2cap_chan_connect+0x56e>
    9aae:	b8 f4 ff ff ff       	mov    $0xfffffff4,%eax
    9ab3:	e9 1e fb ff ff       	jmpq   95d6 <l2cap_chan_connect+0x96>
			l2cap_do_start(chan);
    9ab8:	48 89 df             	mov    %rbx,%rdi
    9abb:	e8 80 e0 ff ff       	callq  7b40 <l2cap_do_start>
	err = 0;
    9ac0:	31 c0                	xor    %eax,%eax
    9ac2:	e9 0f fb ff ff       	jmpq   95d6 <l2cap_chan_connect+0x96>
				timeo = msecs_to_jiffies(conn->disc_timeout);
    9ac7:	41 0f b7 79 44       	movzwl 0x44(%r9),%edi
    9acc:	e8 00 00 00 00       	callq  9ad1 <l2cap_chan_connect+0x591>
					timeo *= 2;
    9ad1:	4c 8b 4d c8          	mov    -0x38(%rbp),%r9
				timeo = msecs_to_jiffies(conn->disc_timeout);
    9ad5:	48 89 c3             	mov    %rax,%rbx
					timeo *= 2;
    9ad8:	48 8d 04 00          	lea    (%rax,%rax,1),%rax
    9adc:	41 80 79 22 00       	cmpb   $0x0,0x22(%r9)
    9ae1:	48 0f 44 d8          	cmove  %rax,%rbx
    9ae5:	e9 c7 fc ff ff       	jmpq   97b1 <l2cap_chan_connect+0x271>
		kfree(c);
    9aea:	48 89 df             	mov    %rbx,%rdi
    9aed:	e8 00 00 00 00       	callq  9af2 <l2cap_chan_connect+0x5b2>
    9af2:	e9 64 fe ff ff       	jmpq   995b <l2cap_chan_connect+0x41b>
	BT_DBG("%s -> %s (type %u) psm 0x%2.2x", batostr(src), batostr(dst),
    9af7:	44 0f b7 67 18       	movzwl 0x18(%rdi),%r12d
    9afc:	48 89 cf             	mov    %rcx,%rdi
    9aff:	e8 00 00 00 00       	callq  9b04 <l2cap_chan_connect+0x5c4>
    9b04:	48 8b 7d b0          	mov    -0x50(%rbp),%rdi
    9b08:	49 89 c6             	mov    %rax,%r14
    9b0b:	e8 00 00 00 00       	callq  9b10 <l2cap_chan_connect+0x5d0>
    9b10:	44 0f b6 45 ac       	movzbl -0x54(%rbp),%r8d
    9b15:	48 89 c2             	mov    %rax,%rdx
    9b18:	45 89 e1             	mov    %r12d,%r9d
    9b1b:	4c 89 f1             	mov    %r14,%rcx
    9b1e:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    9b25:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    9b2c:	31 c0                	xor    %eax,%eax
    9b2e:	e8 00 00 00 00       	callq  9b33 <l2cap_chan_connect+0x5f3>
    9b33:	e9 4a fa ff ff       	jmpq   9582 <l2cap_chan_connect+0x42>
				timeo = msecs_to_jiffies(conn->disc_timeout);
    9b38:	41 0f b7 79 44       	movzwl 0x44(%r9),%edi
    9b3d:	e8 00 00 00 00       	callq  9b42 <l2cap_chan_connect+0x602>
				if (!conn->out)
    9b42:	4c 8b 4d c8          	mov    -0x38(%rbp),%r9
				timeo = msecs_to_jiffies(conn->disc_timeout);
    9b46:	48 89 c3             	mov    %rax,%rbx
					timeo *= 2;
    9b49:	48 8d 04 00          	lea    (%rax,%rax,1),%rax
    9b4d:	41 80 79 22 00       	cmpb   $0x0,0x22(%r9)
    9b52:	48 0f 44 d8          	cmove  %rax,%rbx
    9b56:	e9 12 ff ff ff       	jmpq   9a6d <l2cap_chan_connect+0x52d>
	switch (state) {
    9b5b:	0f b6 43 10          	movzbl 0x10(%rbx),%eax
    9b5f:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    9b66:	83 e8 01             	sub    $0x1,%eax
    9b69:	83 f8 08             	cmp    $0x8,%eax
    9b6c:	77 08                	ja     9b76 <l2cap_chan_connect+0x636>
    9b6e:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    9b75:	00 
	BT_DBG("chan %p state %s timeout %ld", chan,
    9b76:	4c 8b 45 c8          	mov    -0x38(%rbp),%r8
    9b7a:	48 89 da             	mov    %rbx,%rdx
    9b7d:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    9b84:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    9b8b:	31 c0                	xor    %eax,%eax
    9b8d:	4c 89 4d b8          	mov    %r9,-0x48(%rbp)
    9b91:	e8 00 00 00 00       	callq  9b96 <l2cap_chan_connect+0x656>
    9b96:	4c 8b 4d b8          	mov    -0x48(%rbp),%r9
    9b9a:	e9 44 fd ff ff       	jmpq   98e3 <l2cap_chan_connect+0x3a3>
		err = PTR_ERR(hcon);
    9b9f:	44 89 c8             	mov    %r9d,%eax
		goto done;
    9ba2:	e9 2f fa ff ff       	jmpq   95d6 <l2cap_chan_connect+0x96>
    9ba7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    9bae:	00 00 

0000000000009bb0 <__l2cap_wait_ack>:
{
    9bb0:	55                   	push   %rbp
    9bb1:	48 89 e5             	mov    %rsp,%rbp
    9bb4:	41 57                	push   %r15
    9bb6:	41 56                	push   %r14
    9bb8:	41 55                	push   %r13
    9bba:	41 54                	push   %r12
    9bbc:	53                   	push   %rbx
    9bbd:	48 83 ec 48          	sub    $0x48,%rsp
    9bc1:	e8 00 00 00 00       	callq  9bc6 <__l2cap_wait_ack+0x16>
	struct l2cap_chan *chan = l2cap_pi(sk)->chan;
    9bc6:	4c 8b bf b8 02 00 00 	mov    0x2b8(%rdi),%r15
{
    9bcd:	49 89 fe             	mov    %rdi,%r14
}

static inline wait_queue_head_t *sk_sleep(struct sock *sk)
{
	BUILD_BUG_ON(offsetof(struct socket_wq, wait) != 0);
	return &rcu_dereference_raw(sk->sk_wq)->wait;
    9bd0:	48 8b bf b8 00 00 00 	mov    0xb8(%rdi),%rdi
	add_wait_queue(sk_sleep(sk), &wait);
    9bd7:	48 8d 75 a8          	lea    -0x58(%rbp),%rsi
	DECLARE_WAITQUEUE(wait, current);
    9bdb:	48 c7 45 a8 00 00 00 	movq   $0x0,-0x58(%rbp)
    9be2:	00 
    9be3:	48 c7 45 c0 00 00 00 	movq   $0x0,-0x40(%rbp)
    9bea:	00 
    9beb:	48 c7 45 c8 00 00 00 	movq   $0x0,-0x38(%rbp)
    9bf2:	00 
    9bf3:	48 c7 45 b8 00 00 00 	movq   $0x0,-0x48(%rbp)
    9bfa:	00 

DECLARE_PER_CPU(struct task_struct *, current_task);

static __always_inline struct task_struct *get_current(void)
{
	return this_cpu_read_stable(current_task);
    9bfb:	65 4c 8b 2c 25 00 00 	mov    %gs:0x0,%r13
    9c02:	00 00 
    9c04:	4c 89 6d b0          	mov    %r13,-0x50(%rbp)
	add_wait_queue(sk_sleep(sk), &wait);
    9c08:	e8 00 00 00 00       	callq  9c0d <__l2cap_wait_ack+0x5d>
	set_current_state(TASK_INTERRUPTIBLE);
    9c0d:	48 c7 45 90 01 00 00 	movq   $0x1,-0x70(%rbp)
    9c14:	00 
    9c15:	48 8b 45 90          	mov    -0x70(%rbp),%rax
    9c19:	49 87 45 00          	xchg   %rax,0x0(%r13)
	int timeo = HZ/5;
    9c1d:	41 bc c8 00 00 00    	mov    $0xc8,%r12d
	set_current_state(TASK_INTERRUPTIBLE);
    9c23:	48 89 45 90          	mov    %rax,-0x70(%rbp)
    9c27:	48 8b 45 90          	mov    -0x70(%rbp),%rax
	while (chan->unacked_frames > 0 && chan->conn) {
    9c2b:	eb 6d                	jmp    9c9a <__l2cap_wait_ack+0xea>
    9c2d:	0f 1f 00             	nopl   (%rax)
    9c30:	49 83 7f 08 00       	cmpq   $0x0,0x8(%r15)
    9c35:	74 6e                	je     9ca5 <__l2cap_wait_ack+0xf5>
			timeo = HZ/5;
    9c37:	45 85 e4             	test   %r12d,%r12d
    9c3a:	b8 c8 00 00 00       	mov    $0xc8,%eax
    9c3f:	44 0f 44 e0          	cmove  %eax,%r12d
	return test_and_clear_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline int test_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_ti_thread_flag(task_thread_info(tsk), flag);
    9c43:	49 8b 45 08          	mov    0x8(%r13),%rax
		(addr[nr / BITS_PER_LONG])) != 0;
    9c47:	48 8b 58 10          	mov    0x10(%rax),%rbx
    9c4b:	48 c1 eb 02          	shr    $0x2,%rbx
    9c4f:	83 e3 01             	and    $0x1,%ebx
		if (signal_pending(current)) {
    9c52:	85 db                	test   %ebx,%ebx
    9c54:	0f 85 8e 00 00 00    	jne    9ce8 <__l2cap_wait_ack+0x138>
		release_sock(sk);
    9c5a:	4c 89 f7             	mov    %r14,%rdi
    9c5d:	e8 00 00 00 00       	callq  9c62 <__l2cap_wait_ack+0xb2>
		timeo = schedule_timeout(timeo);
    9c62:	49 63 fc             	movslq %r12d,%rdi
    9c65:	e8 00 00 00 00       	callq  9c6a <__l2cap_wait_ack+0xba>
	lock_sock_nested(sk, 0);
    9c6a:	31 f6                	xor    %esi,%esi
    9c6c:	4c 89 f7             	mov    %r14,%rdi
    9c6f:	41 89 c4             	mov    %eax,%r12d
    9c72:	e8 00 00 00 00       	callq  9c77 <__l2cap_wait_ack+0xc7>
		set_current_state(TASK_INTERRUPTIBLE);
    9c77:	48 c7 45 98 01 00 00 	movq   $0x1,-0x68(%rbp)
    9c7e:	00 
    9c7f:	48 8b 45 98          	mov    -0x68(%rbp),%rax
    9c83:	49 87 45 00          	xchg   %rax,0x0(%r13)
    9c87:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    9c8b:	48 8b 45 98          	mov    -0x68(%rbp),%rax
 */

static inline int sock_error(struct sock *sk)
{
	int err;
	if (likely(!sk->sk_err))
    9c8f:	41 8b 86 7c 01 00 00 	mov    0x17c(%r14),%eax
    9c96:	85 c0                	test   %eax,%eax
    9c98:	75 55                	jne    9cef <__l2cap_wait_ack+0x13f>
	while (chan->unacked_frames > 0 && chan->conn) {
    9c9a:	66 41 83 bf a8 00 00 	cmpw   $0x0,0xa8(%r15)
    9ca1:	00 00 
    9ca3:	75 8b                	jne    9c30 <__l2cap_wait_ack+0x80>
    9ca5:	31 db                	xor    %ebx,%ebx
	set_current_state(TASK_RUNNING);
    9ca7:	48 c7 45 a0 00 00 00 	movq   $0x0,-0x60(%rbp)
    9cae:	00 
    9caf:	48 8b 55 a0          	mov    -0x60(%rbp),%rdx
    9cb3:	65 48 8b 04 25 00 00 	mov    %gs:0x0,%rax
    9cba:	00 00 
    9cbc:	48 87 10             	xchg   %rdx,(%rax)
    9cbf:	48 89 55 a0          	mov    %rdx,-0x60(%rbp)
    9cc3:	48 8b 45 a0          	mov    -0x60(%rbp),%rax
	remove_wait_queue(sk_sleep(sk), &wait);
    9cc7:	48 8d 75 a8          	lea    -0x58(%rbp),%rsi
	return &rcu_dereference_raw(sk->sk_wq)->wait;
    9ccb:	49 8b be b8 00 00 00 	mov    0xb8(%r14),%rdi
    9cd2:	e8 00 00 00 00       	callq  9cd7 <__l2cap_wait_ack+0x127>
}
    9cd7:	48 83 c4 48          	add    $0x48,%rsp
    9cdb:	89 d8                	mov    %ebx,%eax
    9cdd:	5b                   	pop    %rbx
    9cde:	41 5c                	pop    %r12
    9ce0:	41 5d                	pop    %r13
    9ce2:	41 5e                	pop    %r14
    9ce4:	41 5f                	pop    %r15
    9ce6:	5d                   	pop    %rbp
    9ce7:	c3                   	retq   
/* Alas, with timeout socket operations are not restartable.
 * Compare this to poll().
 */
static inline int sock_intr_errno(long timeo)
{
	return timeo == MAX_SCHEDULE_TIMEOUT ? -ERESTARTSYS : -EINTR;
    9ce8:	bb fc ff ff ff       	mov    $0xfffffffc,%ebx
    9ced:	eb b8                	jmp    9ca7 <__l2cap_wait_ack+0xf7>
	err = xchg(&sk->sk_err, 0);
    9cef:	41 87 9e 7c 01 00 00 	xchg   %ebx,0x17c(%r14)
		if (err)
    9cf6:	f7 db                	neg    %ebx
    9cf8:	75 ad                	jne    9ca7 <__l2cap_wait_ack+0xf7>
    9cfa:	eb 9e                	jmp    9c9a <__l2cap_wait_ack+0xea>
    9cfc:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000009d00 <l2cap_chan_send>:
{
    9d00:	55                   	push   %rbp
    9d01:	48 89 e5             	mov    %rsp,%rbp
    9d04:	41 57                	push   %r15
    9d06:	41 56                	push   %r14
    9d08:	41 55                	push   %r13
    9d0a:	41 54                	push   %r12
    9d0c:	53                   	push   %rbx
    9d0d:	48 83 ec 68          	sub    $0x68,%rsp
    9d11:	e8 00 00 00 00       	callq  9d16 <l2cap_chan_send+0x16>
	if (chan->chan_type == L2CAP_CHAN_CONN_LESS) {
    9d16:	80 7f 25 02          	cmpb   $0x2,0x25(%rdi)
{
    9d1a:	49 89 fd             	mov    %rdi,%r13
    9d1d:	48 89 75 a8          	mov    %rsi,-0x58(%rbp)
    9d21:	48 89 95 78 ff ff ff 	mov    %rdx,-0x88(%rbp)
    9d28:	89 cb                	mov    %ecx,%ebx
	if (chan->chan_type == L2CAP_CHAN_CONN_LESS) {
    9d2a:	0f 84 2e 02 00 00    	je     9f5e <l2cap_chan_send+0x25e>
	switch (chan->mode) {
    9d30:	0f b6 47 24          	movzbl 0x24(%rdi),%eax
    9d34:	84 c0                	test   %al,%al
    9d36:	74 58                	je     9d90 <l2cap_chan_send+0x90>
    9d38:	8d 50 fd             	lea    -0x3(%rax),%edx
    9d3b:	80 fa 01             	cmp    $0x1,%dl
    9d3e:	76 20                	jbe    9d60 <l2cap_chan_send+0x60>
		BT_DBG("bad state %1.1x", chan->mode);
    9d40:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 9d47 <l2cap_chan_send+0x47>
    9d47:	0f 85 15 0a 00 00    	jne    a762 <l2cap_chan_send+0xa62>
		err = -EBADFD;
    9d4d:	c7 45 88 b3 ff ff ff 	movl   $0xffffffb3,-0x78(%rbp)
    9d54:	eb 22                	jmp    9d78 <l2cap_chan_send+0x78>
    9d56:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    9d5d:	00 00 00 
		if (len > chan->omtu) {
    9d60:	0f b7 47 20          	movzwl 0x20(%rdi),%eax
			return -EMSGSIZE;
    9d64:	c7 45 88 a6 ff ff ff 	movl   $0xffffffa6,-0x78(%rbp)
		if (len > chan->omtu) {
    9d6b:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    9d72:	0f 86 80 03 00 00    	jbe    a0f8 <l2cap_chan_send+0x3f8>
}
    9d78:	8b 45 88             	mov    -0x78(%rbp),%eax
    9d7b:	48 83 c4 68          	add    $0x68,%rsp
    9d7f:	5b                   	pop    %rbx
    9d80:	41 5c                	pop    %r12
    9d82:	41 5d                	pop    %r13
    9d84:	41 5e                	pop    %r14
    9d86:	41 5f                	pop    %r15
    9d88:	5d                   	pop    %rbp
    9d89:	c3                   	retq   
    9d8a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		if (len > chan->omtu)
    9d90:	0f b7 47 20          	movzwl 0x20(%rdi),%eax
			return -EMSGSIZE;
    9d94:	c7 45 88 a6 ff ff ff 	movl   $0xffffffa6,-0x78(%rbp)
		if (len > chan->omtu)
    9d9b:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    9da2:	77 d4                	ja     9d78 <l2cap_chan_send+0x78>
	BT_DBG("chan %p len %d", chan, (int)len);
    9da4:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 9dab <l2cap_chan_send+0xab>
	struct l2cap_conn *conn = chan->conn;
    9dab:	4c 8b 67 08          	mov    0x8(%rdi),%r12
	BT_DBG("chan %p len %d", chan, (int)len);
    9daf:	0f 85 3b 0a 00 00    	jne    a7f0 <l2cap_chan_send+0xaf0>
	count = min_t(unsigned int, (conn->mtu - L2CAP_HDR_SIZE), len);
    9db5:	41 8b 44 24 20       	mov    0x20(%r12),%eax
    9dba:	4c 8b a5 78 ff ff ff 	mov    -0x88(%rbp),%r12
	skb = chan->ops->alloc_skb(chan, count + L2CAP_HDR_SIZE,
    9dc1:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
	count = min_t(unsigned int, (conn->mtu - L2CAP_HDR_SIZE), len);
    9dc5:	83 e8 04             	sub    $0x4,%eax
    9dc8:	44 39 e0             	cmp    %r12d,%eax
	skb = chan->ops->alloc_skb(chan, count + L2CAP_HDR_SIZE,
    9dcb:	8b 57 30             	mov    0x30(%rdi),%edx
    9dce:	4c 89 ef             	mov    %r13,%rdi
	count = min_t(unsigned int, (conn->mtu - L2CAP_HDR_SIZE), len);
    9dd1:	41 0f 43 c4          	cmovae %r12d,%eax
    9dd5:	41 89 c7             	mov    %eax,%r15d
    9dd8:	89 45 94             	mov    %eax,-0x6c(%rbp)
	skb = chan->ops->alloc_skb(chan, count + L2CAP_HDR_SIZE,
    9ddb:	49 8b 85 40 03 00 00 	mov    0x340(%r13),%rax
    9de2:	41 8d 77 04          	lea    0x4(%r15),%esi
    9de6:	83 e2 40             	and    $0x40,%edx
    9de9:	48 63 f6             	movslq %esi,%rsi
    9dec:	ff 50 28             	callq  *0x28(%rax)
	if (IS_ERR(skb))
    9def:	48 3d 00 f0 ff ff    	cmp    $0xfffffffffffff000,%rax
	skb = chan->ops->alloc_skb(chan, count + L2CAP_HDR_SIZE,
    9df5:	49 89 c6             	mov    %rax,%r14
	if (IS_ERR(skb))
    9df8:	0f 87 5c 09 00 00    	ja     a75a <l2cap_chan_send+0xa5a>
	skb->priority = priority;
    9dfe:	89 58 78             	mov    %ebx,0x78(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    9e01:	be 04 00 00 00       	mov    $0x4,%esi
    9e06:	48 89 c7             	mov    %rax,%rdi
    9e09:	e8 00 00 00 00       	callq  9e0e <l2cap_chan_send+0x10e>
	lh->cid = cpu_to_le16(chan->dcid);
    9e0e:	41 0f b7 55 1a       	movzwl 0x1a(%r13),%edx
	lh->len = cpu_to_le16(len);
    9e13:	66 44 89 20          	mov    %r12w,(%rax)
	if (memcpy_fromiovec(skb_put(skb, count), msg->msg_iov, count))
    9e17:	44 89 fe             	mov    %r15d,%esi
    9e1a:	4c 89 f7             	mov    %r14,%rdi
	err = l2cap_skbuff_fromiovec(chan, msg, len, count, skb);
    9e1d:	4c 89 a5 78 ff ff ff 	mov    %r12,-0x88(%rbp)
    9e24:	44 89 65 88          	mov    %r12d,-0x78(%rbp)
	lh->cid = cpu_to_le16(chan->dcid);
    9e28:	66 89 50 02          	mov    %dx,0x2(%rax)
	if (memcpy_fromiovec(skb_put(skb, count), msg->msg_iov, count))
    9e2c:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
	struct l2cap_conn *conn = chan->conn;
    9e30:	49 8b 4d 08          	mov    0x8(%r13),%rcx
	if (memcpy_fromiovec(skb_put(skb, count), msg->msg_iov, count))
    9e34:	48 8b 58 10          	mov    0x10(%rax),%rbx
	struct l2cap_conn *conn = chan->conn;
    9e38:	48 89 4d 98          	mov    %rcx,-0x68(%rbp)
	if (memcpy_fromiovec(skb_put(skb, count), msg->msg_iov, count))
    9e3c:	e8 00 00 00 00       	callq  9e41 <l2cap_chan_send+0x141>
    9e41:	44 89 fa             	mov    %r15d,%edx
    9e44:	48 89 de             	mov    %rbx,%rsi
    9e47:	48 89 c7             	mov    %rax,%rdi
    9e4a:	e8 00 00 00 00       	callq  9e4f <l2cap_chan_send+0x14f>
    9e4f:	85 c0                	test   %eax,%eax
    9e51:	0f 85 cf 00 00 00    	jne    9f26 <l2cap_chan_send+0x226>
	return skb->head + skb->end;
    9e57:	41 8b 8e d0 00 00 00 	mov    0xd0(%r14),%ecx
	while (len) {
    9e5e:	8b 85 78 ff ff ff    	mov    -0x88(%rbp),%eax
    9e64:	49 03 8e d8 00 00 00 	add    0xd8(%r14),%rcx
    9e6b:	44 29 f8             	sub    %r15d,%eax
	frag = &skb_shinfo(skb)->frag_list;
    9e6e:	4c 8d 61 08          	lea    0x8(%rcx),%r12
	while (len) {
    9e72:	0f 84 d6 00 00 00    	je     9f4e <l2cap_chan_send+0x24e>
    9e78:	41 89 c7             	mov    %eax,%r15d
    9e7b:	4c 89 e0             	mov    %r12,%rax
    9e7e:	4d 89 f4             	mov    %r14,%r12
    9e81:	49 89 c6             	mov    %rax,%r14
    9e84:	eb 3a                	jmp    9ec0 <l2cap_chan_send+0x1c0>
    9e86:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    9e8d:	00 00 00 
		(*frag)->priority = skb->priority;
    9e90:	49 8b 06             	mov    (%r14),%rax
    9e93:	41 8b 54 24 78       	mov    0x78(%r12),%edx
		sent += count;
    9e98:	01 5d 94             	add    %ebx,-0x6c(%rbp)
		(*frag)->priority = skb->priority;
    9e9b:	89 50 78             	mov    %edx,0x78(%rax)
		skb->len += (*frag)->len;
    9e9e:	49 8b 06             	mov    (%r14),%rax
    9ea1:	8b 40 68             	mov    0x68(%rax),%eax
    9ea4:	41 01 44 24 68       	add    %eax,0x68(%r12)
		skb->data_len += (*frag)->len;
    9ea9:	49 8b 06             	mov    (%r14),%rax
    9eac:	8b 40 68             	mov    0x68(%rax),%eax
    9eaf:	41 01 44 24 6c       	add    %eax,0x6c(%r12)
	while (len) {
    9eb4:	41 29 df             	sub    %ebx,%r15d
		frag = &(*frag)->next;
    9eb7:	4d 8b 36             	mov    (%r14),%r14
	while (len) {
    9eba:	0f 84 80 00 00 00    	je     9f40 <l2cap_chan_send+0x240>
		count = min_t(unsigned int, conn->mtu, len);
    9ec0:	48 8b 45 98          	mov    -0x68(%rbp),%rax
		tmp = chan->ops->alloc_skb(chan, count,
    9ec4:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
		count = min_t(unsigned int, conn->mtu, len);
    9ec8:	8b 58 20             	mov    0x20(%rax),%ebx
		tmp = chan->ops->alloc_skb(chan, count,
    9ecb:	8b 57 30             	mov    0x30(%rdi),%edx
    9ece:	4c 89 ef             	mov    %r13,%rdi
    9ed1:	49 8b 85 40 03 00 00 	mov    0x340(%r13),%rax
		count = min_t(unsigned int, conn->mtu, len);
    9ed8:	41 39 df             	cmp    %ebx,%r15d
    9edb:	41 0f 46 df          	cmovbe %r15d,%ebx
		tmp = chan->ops->alloc_skb(chan, count,
    9edf:	83 e2 40             	and    $0x40,%edx
    9ee2:	48 63 f3             	movslq %ebx,%rsi
    9ee5:	ff 50 28             	callq  *0x28(%rax)
		if (IS_ERR(tmp))
    9ee8:	48 3d 00 f0 ff ff    	cmp    $0xfffffffffffff000,%rax
    9eee:	0f 87 16 08 00 00    	ja     a70a <l2cap_chan_send+0xa0a>
		if (memcpy_fromiovec(skb_put(*frag, count), msg->msg_iov, count))
    9ef4:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
		*frag = tmp;
    9ef8:	49 89 06             	mov    %rax,(%r14)
		if (memcpy_fromiovec(skb_put(*frag, count), msg->msg_iov, count))
    9efb:	89 de                	mov    %ebx,%esi
    9efd:	48 8b 7f 10          	mov    0x10(%rdi),%rdi
    9f01:	48 89 7d a0          	mov    %rdi,-0x60(%rbp)
    9f05:	48 89 c7             	mov    %rax,%rdi
    9f08:	e8 00 00 00 00       	callq  9f0d <l2cap_chan_send+0x20d>
    9f0d:	48 8b 75 a0          	mov    -0x60(%rbp),%rsi
    9f11:	89 da                	mov    %ebx,%edx
    9f13:	48 89 c7             	mov    %rax,%rdi
    9f16:	e8 00 00 00 00       	callq  9f1b <l2cap_chan_send+0x21b>
    9f1b:	85 c0                	test   %eax,%eax
    9f1d:	0f 84 6d ff ff ff    	je     9e90 <l2cap_chan_send+0x190>
    9f23:	4d 89 e6             	mov    %r12,%r14
		kfree_skb(skb);
    9f26:	4c 89 f7             	mov    %r14,%rdi
    9f29:	e8 00 00 00 00       	callq  9f2e <l2cap_chan_send+0x22e>
    9f2e:	49 c7 c1 f2 ff ff ff 	mov    $0xfffffffffffffff2,%r9
			return PTR_ERR(skb);
    9f35:	44 89 4d 88          	mov    %r9d,-0x78(%rbp)
    9f39:	e9 3a fe ff ff       	jmpq   9d78 <l2cap_chan_send+0x78>
    9f3e:	66 90                	xchg   %ax,%ax
    9f40:	4d 89 e6             	mov    %r12,%r14
		sent += count;
    9f43:	8b 45 94             	mov    -0x6c(%rbp),%eax
	if (unlikely(err < 0)) {
    9f46:	85 c0                	test   %eax,%eax
    9f48:	0f 88 86 08 00 00    	js     a7d4 <l2cap_chan_send+0xad4>
	return skb;
    9f4e:	4c 89 f6             	mov    %r14,%rsi
		l2cap_do_send(chan, skb);
    9f51:	4c 89 ef             	mov    %r13,%rdi
    9f54:	e8 a7 65 ff ff       	callq  500 <l2cap_do_send>
		break;
    9f59:	e9 1a fe ff ff       	jmpq   9d78 <l2cap_chan_send+0x78>
	BT_DBG("chan %p len %d priority %u", chan, (int)len, priority);
    9f5e:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # 9f65 <l2cap_chan_send+0x265>
	struct l2cap_conn *conn = chan->conn;
    9f65:	4c 8b 67 08          	mov    0x8(%rdi),%r12
	BT_DBG("chan %p len %d priority %u", chan, (int)len, priority);
    9f69:	0f 85 3f 08 00 00    	jne    a7ae <l2cap_chan_send+0xaae>
	count = min_t(unsigned int, (conn->mtu - hlen), len);
    9f6f:	41 8b 44 24 20       	mov    0x20(%r12),%eax
    9f74:	4c 8b a5 78 ff ff ff 	mov    -0x88(%rbp),%r12
	skb = chan->ops->alloc_skb(chan, count + hlen,
    9f7b:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
	count = min_t(unsigned int, (conn->mtu - hlen), len);
    9f7f:	83 e8 06             	sub    $0x6,%eax
    9f82:	44 39 e0             	cmp    %r12d,%eax
	skb = chan->ops->alloc_skb(chan, count + hlen,
    9f85:	8b 57 30             	mov    0x30(%rdi),%edx
    9f88:	4c 89 ef             	mov    %r13,%rdi
	count = min_t(unsigned int, (conn->mtu - hlen), len);
    9f8b:	41 0f 43 c4          	cmovae %r12d,%eax
    9f8f:	41 89 c7             	mov    %eax,%r15d
    9f92:	89 45 94             	mov    %eax,-0x6c(%rbp)
	skb = chan->ops->alloc_skb(chan, count + hlen,
    9f95:	49 8b 85 40 03 00 00 	mov    0x340(%r13),%rax
    9f9c:	41 8d 77 06          	lea    0x6(%r15),%esi
    9fa0:	83 e2 40             	and    $0x40,%edx
    9fa3:	48 63 f6             	movslq %esi,%rsi
    9fa6:	ff 50 28             	callq  *0x28(%rax)
	if (IS_ERR(skb))
    9fa9:	48 3d 00 f0 ff ff    	cmp    $0xfffffffffffff000,%rax
	skb = chan->ops->alloc_skb(chan, count + hlen,
    9faf:	49 89 c6             	mov    %rax,%r14
	if (IS_ERR(skb))
    9fb2:	0f 87 a2 07 00 00    	ja     a75a <l2cap_chan_send+0xa5a>
	skb->priority = priority;
    9fb8:	89 58 78             	mov    %ebx,0x78(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    9fbb:	be 04 00 00 00       	mov    $0x4,%esi
    9fc0:	48 89 c7             	mov    %rax,%rdi
    9fc3:	e8 00 00 00 00       	callq  9fc8 <l2cap_chan_send+0x2c8>
	lh->cid = cpu_to_le16(chan->dcid);
    9fc8:	41 0f b7 55 1a       	movzwl 0x1a(%r13),%edx
	lh->len = cpu_to_le16(len + L2CAP_PSMLEN_SIZE);
    9fcd:	44 89 e1             	mov    %r12d,%ecx
	put_unaligned(chan->psm, skb_put(skb, L2CAP_PSMLEN_SIZE));
    9fd0:	be 02 00 00 00       	mov    $0x2,%esi
    9fd5:	4c 89 f7             	mov    %r14,%rdi
	lh->cid = cpu_to_le16(chan->dcid);
    9fd8:	66 89 50 02          	mov    %dx,0x2(%rax)
	lh->len = cpu_to_le16(len + L2CAP_PSMLEN_SIZE);
    9fdc:	8d 51 02             	lea    0x2(%rcx),%edx
    9fdf:	66 89 10             	mov    %dx,(%rax)
	put_unaligned(chan->psm, skb_put(skb, L2CAP_PSMLEN_SIZE));
    9fe2:	e8 00 00 00 00       	callq  9fe7 <l2cap_chan_send+0x2e7>
    9fe7:	41 0f b7 55 18       	movzwl 0x18(%r13),%edx
	if (memcpy_fromiovec(skb_put(skb, count), msg->msg_iov, count))
    9fec:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    9ff0:	44 89 fe             	mov    %r15d,%esi
	err = l2cap_skbuff_fromiovec(chan, msg, len, count, skb);
    9ff3:	4c 89 a5 78 ff ff ff 	mov    %r12,-0x88(%rbp)
    9ffa:	44 89 65 88          	mov    %r12d,-0x78(%rbp)
	put_unaligned(chan->psm, skb_put(skb, L2CAP_PSMLEN_SIZE));
    9ffe:	88 10                	mov    %dl,(%rax)
	if (memcpy_fromiovec(skb_put(skb, count), msg->msg_iov, count))
    a000:	48 8b 5f 10          	mov    0x10(%rdi),%rbx
    a004:	4c 89 f7             	mov    %r14,%rdi
	struct l2cap_conn *conn = chan->conn;
    a007:	49 8b 45 08          	mov    0x8(%r13),%rax
    a00b:	48 89 45 98          	mov    %rax,-0x68(%rbp)
	if (memcpy_fromiovec(skb_put(skb, count), msg->msg_iov, count))
    a00f:	e8 00 00 00 00       	callq  a014 <l2cap_chan_send+0x314>
    a014:	44 89 fa             	mov    %r15d,%edx
    a017:	48 89 de             	mov    %rbx,%rsi
    a01a:	48 89 c7             	mov    %rax,%rdi
    a01d:	e8 00 00 00 00       	callq  a022 <l2cap_chan_send+0x322>
    a022:	85 c0                	test   %eax,%eax
    a024:	0f 85 fc fe ff ff    	jne    9f26 <l2cap_chan_send+0x226>
    a02a:	41 8b 8e d0 00 00 00 	mov    0xd0(%r14),%ecx
	while (len) {
    a031:	8b 85 78 ff ff ff    	mov    -0x88(%rbp),%eax
    a037:	49 03 8e d8 00 00 00 	add    0xd8(%r14),%rcx
    a03e:	44 29 f8             	sub    %r15d,%eax
	frag = &skb_shinfo(skb)->frag_list;
    a041:	4c 8d 61 08          	lea    0x8(%rcx),%r12
	while (len) {
    a045:	0f 84 f8 fe ff ff    	je     9f43 <l2cap_chan_send+0x243>
    a04b:	41 89 c7             	mov    %eax,%r15d
    a04e:	4c 89 e0             	mov    %r12,%rax
    a051:	4d 89 f4             	mov    %r14,%r12
    a054:	49 89 c6             	mov    %rax,%r14
    a057:	eb 37                	jmp    a090 <l2cap_chan_send+0x390>
    a059:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		(*frag)->priority = skb->priority;
    a060:	49 8b 06             	mov    (%r14),%rax
    a063:	41 8b 54 24 78       	mov    0x78(%r12),%edx
		sent += count;
    a068:	01 5d 94             	add    %ebx,-0x6c(%rbp)
		(*frag)->priority = skb->priority;
    a06b:	89 50 78             	mov    %edx,0x78(%rax)
		skb->len += (*frag)->len;
    a06e:	49 8b 06             	mov    (%r14),%rax
    a071:	8b 40 68             	mov    0x68(%rax),%eax
    a074:	41 01 44 24 68       	add    %eax,0x68(%r12)
		skb->data_len += (*frag)->len;
    a079:	49 8b 06             	mov    (%r14),%rax
    a07c:	8b 40 68             	mov    0x68(%rax),%eax
    a07f:	41 01 44 24 6c       	add    %eax,0x6c(%r12)
	while (len) {
    a084:	41 29 df             	sub    %ebx,%r15d
		frag = &(*frag)->next;
    a087:	4d 8b 36             	mov    (%r14),%r14
	while (len) {
    a08a:	0f 84 b0 fe ff ff    	je     9f40 <l2cap_chan_send+0x240>
		count = min_t(unsigned int, conn->mtu, len);
    a090:	48 8b 45 98          	mov    -0x68(%rbp),%rax
		tmp = chan->ops->alloc_skb(chan, count,
    a094:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
		count = min_t(unsigned int, conn->mtu, len);
    a098:	8b 58 20             	mov    0x20(%rax),%ebx
		tmp = chan->ops->alloc_skb(chan, count,
    a09b:	8b 57 30             	mov    0x30(%rdi),%edx
    a09e:	4c 89 ef             	mov    %r13,%rdi
    a0a1:	49 8b 85 40 03 00 00 	mov    0x340(%r13),%rax
		count = min_t(unsigned int, conn->mtu, len);
    a0a8:	41 39 df             	cmp    %ebx,%r15d
    a0ab:	41 0f 46 df          	cmovbe %r15d,%ebx
		tmp = chan->ops->alloc_skb(chan, count,
    a0af:	83 e2 40             	and    $0x40,%edx
    a0b2:	48 63 f3             	movslq %ebx,%rsi
    a0b5:	ff 50 28             	callq  *0x28(%rax)
		if (IS_ERR(tmp))
    a0b8:	48 3d 00 f0 ff ff    	cmp    $0xfffffffffffff000,%rax
    a0be:	0f 87 46 06 00 00    	ja     a70a <l2cap_chan_send+0xa0a>
		if (memcpy_fromiovec(skb_put(*frag, count), msg->msg_iov, count))
    a0c4:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
		*frag = tmp;
    a0c8:	49 89 06             	mov    %rax,(%r14)
		if (memcpy_fromiovec(skb_put(*frag, count), msg->msg_iov, count))
    a0cb:	89 de                	mov    %ebx,%esi
    a0cd:	48 8b 7f 10          	mov    0x10(%rdi),%rdi
    a0d1:	48 89 7d a0          	mov    %rdi,-0x60(%rbp)
    a0d5:	48 89 c7             	mov    %rax,%rdi
    a0d8:	e8 00 00 00 00       	callq  a0dd <l2cap_chan_send+0x3dd>
    a0dd:	48 8b 75 a0          	mov    -0x60(%rbp),%rsi
    a0e1:	89 da                	mov    %ebx,%edx
    a0e3:	48 89 c7             	mov    %rax,%rdi
    a0e6:	e8 00 00 00 00       	callq  a0eb <l2cap_chan_send+0x3eb>
    a0eb:	85 c0                	test   %eax,%eax
    a0ed:	0f 84 6d ff ff ff    	je     a060 <l2cap_chan_send+0x360>
    a0f3:	e9 2b fe ff ff       	jmpq   9f23 <l2cap_chan_send+0x223>
	BT_DBG("chan %p, msg %p, len %d", chan, msg, (int)len);
    a0f8:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # a0ff <l2cap_chan_send+0x3ff>
	list->prev = list->next = (struct sk_buff *)list;
    a0ff:	48 8d 45 b8          	lea    -0x48(%rbp),%rax
	list->qlen = 0;
    a103:	c7 45 c8 00 00 00 00 	movl   $0x0,-0x38(%rbp)
	list->prev = list->next = (struct sk_buff *)list;
    a10a:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    a10e:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    a112:	0f 85 6e 06 00 00    	jne    a786 <l2cap_chan_send+0xa86>
	pdu_len = chan->conn->mtu;
    a118:	49 8b 5d 08          	mov    0x8(%r13),%rbx
	pdu_len = min_t(size_t, pdu_len, L2CAP_BREDR_MAX_PAYLOAD);
    a11c:	ba fb 03 00 00       	mov    $0x3fb,%edx
	pdu_len = chan->conn->mtu;
    a121:	8b 43 20             	mov    0x20(%rbx),%eax
	pdu_len = min_t(size_t, pdu_len, L2CAP_BREDR_MAX_PAYLOAD);
    a124:	48 3d fb 03 00 00    	cmp    $0x3fb,%rax
    a12a:	48 0f 47 c2          	cmova  %rdx,%rax
	pdu_len = min_t(size_t, pdu_len, chan->remote_mps);
    a12e:	41 0f b7 95 cc 00 00 	movzwl 0xcc(%r13),%edx
    a135:	00 
	pdu_len -= L2CAP_EXT_HDR_SIZE + L2CAP_FCS_SIZE;
    a136:	48 83 e8 0a          	sub    $0xa,%rax
	pdu_len = min_t(size_t, pdu_len, chan->remote_mps);
    a13a:	48 39 d0             	cmp    %rdx,%rax
    a13d:	48 0f 47 c2          	cmova  %rdx,%rax
	if (len <= pdu_len) {
    a141:	48 39 85 78 ff ff ff 	cmp    %rax,-0x88(%rbp)
    a148:	0f 87 75 02 00 00    	ja     a3c3 <l2cap_chan_send+0x6c3>
	while (len > 0) {
    a14e:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
		sdu_len = 0;
    a155:	31 ff                	xor    %edi,%edi
		sar = L2CAP_SAR_UNSEGMENTED;
    a157:	c6 45 91 00          	movb   $0x0,-0x6f(%rbp)
		sdu_len = 0;
    a15b:	66 89 7d 92          	mov    %di,-0x6e(%rbp)
	while (len > 0) {
    a15f:	48 85 c0             	test   %rax,%rax
    a162:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    a166:	0f 84 65 03 00 00    	je     a4d1 <l2cap_chan_send+0x7d1>
		sar = L2CAP_SAR_START;
    a16c:	48 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%rax
    a173:	48 89 45 80          	mov    %rax,-0x80(%rbp)
    a177:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    a17e:	00 00 
	BT_DBG("chan %p len %d", chan, (int)len);
    a180:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # a187 <l2cap_chan_send+0x487>
    a187:	0f 85 85 05 00 00    	jne    a712 <l2cap_chan_send+0xa12>
	if (!conn)
    a18d:	48 85 db             	test   %rbx,%rbx
    a190:	0f 84 2f 03 00 00    	je     a4c5 <l2cap_chan_send+0x7c5>
    a196:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
	count = min_t(unsigned int, (conn->mtu - hlen), len);
    a19d:	8b 5b 20             	mov    0x20(%rbx),%ebx
	skb = chan->ops->alloc_skb(chan, count + hlen,
    a1a0:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    a1a4:	83 e0 10             	and    $0x10,%eax
		hlen = L2CAP_EXT_HDR_SIZE;
    a1a7:	48 83 f8 01          	cmp    $0x1,%rax
	skb = chan->ops->alloc_skb(chan, count + hlen,
    a1ab:	8b 57 30             	mov    0x30(%rdi),%edx
    a1ae:	4c 89 ef             	mov    %r13,%rdi
		hlen = L2CAP_EXT_HDR_SIZE;
    a1b1:	45 19 e4             	sbb    %r12d,%r12d
    a1b4:	41 83 e4 fe          	and    $0xfffffffe,%r12d
    a1b8:	41 83 c4 08          	add    $0x8,%r12d
		hlen += L2CAP_SDULEN_SIZE;
    a1bc:	66 83 7d 92 00       	cmpw   $0x0,-0x6e(%rbp)
    a1c1:	41 8d 44 24 02       	lea    0x2(%r12),%eax
    a1c6:	44 0f 45 e0          	cmovne %eax,%r12d
		hlen += L2CAP_FCS_SIZE;
    a1ca:	41 80 7d 6f 01       	cmpb   $0x1,0x6f(%r13)
    a1cf:	41 8d 44 24 02       	lea    0x2(%r12),%eax
    a1d4:	44 0f 44 e0          	cmove  %eax,%r12d
	count = min_t(unsigned int, (conn->mtu - hlen), len);
    a1d8:	48 8b 45 88          	mov    -0x78(%rbp),%rax
    a1dc:	44 29 e3             	sub    %r12d,%ebx
    a1df:	39 c3                	cmp    %eax,%ebx
    a1e1:	0f 47 d8             	cmova  %eax,%ebx
	skb = chan->ops->alloc_skb(chan, count + hlen,
    a1e4:	49 8b 85 40 03 00 00 	mov    0x340(%r13),%rax
    a1eb:	83 e2 40             	and    $0x40,%edx
    a1ee:	41 8d 34 1c          	lea    (%r12,%rbx,1),%esi
	count = min_t(unsigned int, (conn->mtu - hlen), len);
    a1f2:	89 5d 94             	mov    %ebx,-0x6c(%rbp)
	skb = chan->ops->alloc_skb(chan, count + hlen,
    a1f5:	48 63 f6             	movslq %esi,%rsi
    a1f8:	ff 50 28             	callq  *0x28(%rax)
	if (IS_ERR(skb))
    a1fb:	48 3d 00 f0 ff ff    	cmp    $0xfffffffffffff000,%rax
	skb = chan->ops->alloc_skb(chan, count + hlen,
    a201:	49 89 c6             	mov    %rax,%r14
	if (IS_ERR(skb))
    a204:	0f 87 28 05 00 00    	ja     a732 <l2cap_chan_send+0xa32>
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    a20a:	be 04 00 00 00       	mov    $0x4,%esi
    a20f:	48 89 c7             	mov    %rax,%rdi
    a212:	e8 00 00 00 00       	callq  a217 <l2cap_chan_send+0x517>
	lh->len = cpu_to_le16(len + (hlen - L2CAP_HDR_SIZE));
    a217:	0f b7 4d 88          	movzwl -0x78(%rbp),%ecx
	lh->cid = cpu_to_le16(chan->dcid);
    a21b:	41 0f b7 55 1a       	movzwl 0x1a(%r13),%edx
	__put_control(chan, 0, skb_put(skb, __ctrl_size(chan)));
    a220:	4c 89 f7             	mov    %r14,%rdi
	lh->len = cpu_to_le16(len + (hlen - L2CAP_HDR_SIZE));
    a223:	46 8d 64 21 fc       	lea    -0x4(%rcx,%r12,1),%r12d
	lh->cid = cpu_to_le16(chan->dcid);
    a228:	66 89 50 02          	mov    %dx,0x2(%rax)
	lh->len = cpu_to_le16(len + (hlen - L2CAP_HDR_SIZE));
    a22c:	66 44 89 20          	mov    %r12w,(%rax)
    a230:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
    a237:	83 e0 10             	and    $0x10,%eax
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    a23a:	48 83 f8 01          	cmp    $0x1,%rax
    a23e:	19 f6                	sbb    %esi,%esi
    a240:	83 e6 fe             	and    $0xfffffffe,%esi
    a243:	83 c6 04             	add    $0x4,%esi
	__put_control(chan, 0, skb_put(skb, __ctrl_size(chan)));
    a246:	e8 00 00 00 00       	callq  a24b <l2cap_chan_send+0x54b>
    a24b:	49 8b 95 90 00 00 00 	mov    0x90(%r13),%rdx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    a252:	83 e2 10             	and    $0x10,%edx
    a255:	0f 84 85 01 00 00    	je     a3e0 <l2cap_chan_send+0x6e0>
	if (sdulen)
    a25b:	66 83 7d 92 00       	cmpw   $0x0,-0x6e(%rbp)
	*((__le32 *)p) = cpu_to_le32(val);
    a260:	c7 00 00 00 00 00    	movl   $0x0,(%rax)
    a266:	0f 85 84 01 00 00    	jne    a3f0 <l2cap_chan_send+0x6f0>
	struct l2cap_conn *conn = chan->conn;
    a26c:	49 8b 45 08          	mov    0x8(%r13),%rax
	if (memcpy_fromiovec(skb_put(skb, count), msg->msg_iov, count))
    a270:	89 de                	mov    %ebx,%esi
    a272:	4c 89 f7             	mov    %r14,%rdi
	struct l2cap_conn *conn = chan->conn;
    a275:	48 89 45 98          	mov    %rax,-0x68(%rbp)
	if (memcpy_fromiovec(skb_put(skb, count), msg->msg_iov, count))
    a279:	48 8b 45 a8          	mov    -0x58(%rbp),%rax
    a27d:	4c 8b 60 10          	mov    0x10(%rax),%r12
    a281:	e8 00 00 00 00       	callq  a286 <l2cap_chan_send+0x586>
    a286:	89 da                	mov    %ebx,%edx
    a288:	48 89 c7             	mov    %rax,%rdi
    a28b:	4c 89 e6             	mov    %r12,%rsi
    a28e:	e8 00 00 00 00       	callq  a293 <l2cap_chan_send+0x593>
    a293:	85 c0                	test   %eax,%eax
    a295:	0f 85 c0 00 00 00    	jne    a35b <l2cap_chan_send+0x65b>
	return skb->head + skb->end;
    a29b:	41 8b 8e d0 00 00 00 	mov    0xd0(%r14),%ecx
	while (len) {
    a2a2:	44 8b 65 88          	mov    -0x78(%rbp),%r12d
    a2a6:	49 03 8e d8 00 00 00 	add    0xd8(%r14),%rcx
    a2ad:	41 29 dc             	sub    %ebx,%r12d
	frag = &skb_shinfo(skb)->frag_list;
    a2b0:	4c 8d 79 08          	lea    0x8(%rcx),%r15
	while (len) {
    a2b4:	0f 84 5c 01 00 00    	je     a416 <l2cap_chan_send+0x716>
    a2ba:	4c 89 f8             	mov    %r15,%rax
    a2bd:	4d 89 f7             	mov    %r14,%r15
    a2c0:	49 89 c6             	mov    %rax,%r14
    a2c3:	eb 30                	jmp    a2f5 <l2cap_chan_send+0x5f5>
    a2c5:	0f 1f 00             	nopl   (%rax)
		(*frag)->priority = skb->priority;
    a2c8:	49 8b 06             	mov    (%r14),%rax
    a2cb:	41 8b 57 78          	mov    0x78(%r15),%edx
		sent += count;
    a2cf:	01 5d 94             	add    %ebx,-0x6c(%rbp)
		(*frag)->priority = skb->priority;
    a2d2:	89 50 78             	mov    %edx,0x78(%rax)
		skb->len += (*frag)->len;
    a2d5:	49 8b 06             	mov    (%r14),%rax
    a2d8:	8b 40 68             	mov    0x68(%rax),%eax
    a2db:	41 01 47 68          	add    %eax,0x68(%r15)
		skb->data_len += (*frag)->len;
    a2df:	49 8b 06             	mov    (%r14),%rax
    a2e2:	8b 40 68             	mov    0x68(%rax),%eax
    a2e5:	41 01 47 6c          	add    %eax,0x6c(%r15)
	while (len) {
    a2e9:	41 29 dc             	sub    %ebx,%r12d
		frag = &(*frag)->next;
    a2ec:	4d 8b 36             	mov    (%r14),%r14
	while (len) {
    a2ef:	0f 84 1b 01 00 00    	je     a410 <l2cap_chan_send+0x710>
		count = min_t(unsigned int, conn->mtu, len);
    a2f5:	48 8b 45 98          	mov    -0x68(%rbp),%rax
		tmp = chan->ops->alloc_skb(chan, count,
    a2f9:	48 8b 4d a8          	mov    -0x58(%rbp),%rcx
    a2fd:	4c 89 ef             	mov    %r13,%rdi
		count = min_t(unsigned int, conn->mtu, len);
    a300:	8b 58 20             	mov    0x20(%rax),%ebx
		tmp = chan->ops->alloc_skb(chan, count,
    a303:	8b 51 30             	mov    0x30(%rcx),%edx
    a306:	49 8b 85 40 03 00 00 	mov    0x340(%r13),%rax
		count = min_t(unsigned int, conn->mtu, len);
    a30d:	41 39 dc             	cmp    %ebx,%r12d
    a310:	41 0f 46 dc          	cmovbe %r12d,%ebx
		tmp = chan->ops->alloc_skb(chan, count,
    a314:	83 e2 40             	and    $0x40,%edx
    a317:	48 63 f3             	movslq %ebx,%rsi
    a31a:	ff 50 28             	callq  *0x28(%rax)
		if (IS_ERR(tmp))
    a31d:	48 3d 00 f0 ff ff    	cmp    $0xfffffffffffff000,%rax
    a323:	0f 87 d7 03 00 00    	ja     a700 <l2cap_chan_send+0xa00>
		if (memcpy_fromiovec(skb_put(*frag, count), msg->msg_iov, count))
    a329:	48 8b 4d a8          	mov    -0x58(%rbp),%rcx
		*frag = tmp;
    a32d:	49 89 06             	mov    %rax,(%r14)
		if (memcpy_fromiovec(skb_put(*frag, count), msg->msg_iov, count))
    a330:	89 de                	mov    %ebx,%esi
    a332:	48 89 c7             	mov    %rax,%rdi
    a335:	48 8b 49 10          	mov    0x10(%rcx),%rcx
    a339:	48 89 4d a0          	mov    %rcx,-0x60(%rbp)
    a33d:	e8 00 00 00 00       	callq  a342 <l2cap_chan_send+0x642>
    a342:	48 8b 75 a0          	mov    -0x60(%rbp),%rsi
    a346:	89 da                	mov    %ebx,%edx
    a348:	48 89 c7             	mov    %rax,%rdi
    a34b:	e8 00 00 00 00       	callq  a350 <l2cap_chan_send+0x650>
    a350:	85 c0                	test   %eax,%eax
    a352:	0f 84 70 ff ff ff    	je     a2c8 <l2cap_chan_send+0x5c8>
    a358:	4d 89 fe             	mov    %r15,%r14
		kfree_skb(skb);
    a35b:	4c 89 f7             	mov    %r14,%rdi
    a35e:	48 c7 c3 f2 ff ff ff 	mov    $0xfffffffffffffff2,%rbx
    a365:	e8 00 00 00 00       	callq  a36a <l2cap_chan_send+0x66a>
    a36a:	89 5d 88             	mov    %ebx,-0x78(%rbp)
    a36d:	eb 2c                	jmp    a39b <l2cap_chan_send+0x69b>
    a36f:	90                   	nop
	if (skb)
    a370:	48 85 ff             	test   %rdi,%rdi
    a373:	74 33                	je     a3a8 <l2cap_chan_send+0x6a8>
	list->qlen--;
    a375:	83 6d c8 01          	subl   $0x1,-0x38(%rbp)
	next	   = skb->next;
    a379:	48 8b 17             	mov    (%rdi),%rdx
	prev	   = skb->prev;
    a37c:	48 8b 47 08          	mov    0x8(%rdi),%rax
	skb->next  = skb->prev = NULL;
    a380:	48 c7 07 00 00 00 00 	movq   $0x0,(%rdi)
    a387:	48 c7 47 08 00 00 00 	movq   $0x0,0x8(%rdi)
    a38e:	00 
	next->prev = prev;
    a38f:	48 89 42 08          	mov    %rax,0x8(%rdx)
	prev->next = next;
    a393:	48 89 10             	mov    %rdx,(%rax)
extern void skb_queue_purge(struct sk_buff_head *list);
static inline void __skb_queue_purge(struct sk_buff_head *list)
{
	struct sk_buff *skb;
	while ((skb = __skb_dequeue(list)) != NULL)
		kfree_skb(skb);
    a396:	e8 00 00 00 00       	callq  a39b <l2cap_chan_send+0x69b>
	struct sk_buff *skb = list_->next;
    a39b:	48 8b 7d b8          	mov    -0x48(%rbp),%rdi
	if (skb == (struct sk_buff *)list_)
    a39f:	48 8d 45 b8          	lea    -0x48(%rbp),%rax
    a3a3:	48 39 c7             	cmp    %rax,%rdi
    a3a6:	75 c8                	jne    a370 <l2cap_chan_send+0x670>
		if (chan->state != BT_CONNECTED) {
    a3a8:	41 80 7d 10 01       	cmpb   $0x1,0x10(%r13)
    a3ad:	0f 85 82 02 00 00    	jne    a635 <l2cap_chan_send+0x935>
		if (err)
    a3b3:	8b 45 88             	mov    -0x78(%rbp),%eax
    a3b6:	85 c0                	test   %eax,%eax
    a3b8:	0f 84 22 01 00 00    	je     a4e0 <l2cap_chan_send+0x7e0>
    a3be:	e9 b5 f9 ff ff       	jmpq   9d78 <l2cap_chan_send+0x78>
		sdu_len = len;
    a3c3:	0f b7 bd 78 ff ff ff 	movzwl -0x88(%rbp),%edi
		pdu_len -= L2CAP_SDULEN_SIZE;
    a3ca:	48 83 e8 02          	sub    $0x2,%rax
		sar = L2CAP_SAR_START;
    a3ce:	c6 45 91 01          	movb   $0x1,-0x6f(%rbp)
		pdu_len -= L2CAP_SDULEN_SIZE;
    a3d2:	48 89 45 88          	mov    %rax,-0x78(%rbp)
		sdu_len = len;
    a3d6:	66 89 7d 92          	mov    %di,-0x6e(%rbp)
    a3da:	e9 8d fd ff ff       	jmpq   a16c <l2cap_chan_send+0x46c>
    a3df:	90                   	nop
	*((__le16 *)p) = cpu_to_le16(val);
    a3e0:	31 f6                	xor    %esi,%esi
	if (sdulen)
    a3e2:	66 83 7d 92 00       	cmpw   $0x0,-0x6e(%rbp)
    a3e7:	66 89 30             	mov    %si,(%rax)
    a3ea:	0f 84 7c fe ff ff    	je     a26c <l2cap_chan_send+0x56c>
		put_unaligned_le16(sdulen, skb_put(skb, L2CAP_SDULEN_SIZE));
    a3f0:	4c 89 f7             	mov    %r14,%rdi
    a3f3:	be 02 00 00 00       	mov    $0x2,%esi
    a3f8:	e8 00 00 00 00       	callq  a3fd <l2cap_chan_send+0x6fd>
    a3fd:	0f b7 7d 92          	movzwl -0x6e(%rbp),%edi
    a401:	66 89 38             	mov    %di,(%rax)
    a404:	e9 63 fe ff ff       	jmpq   a26c <l2cap_chan_send+0x56c>
    a409:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		sent += count;
    a410:	8b 5d 94             	mov    -0x6c(%rbp),%ebx
    a413:	4d 89 fe             	mov    %r15,%r14
	if (unlikely(err < 0)) {
    a416:	85 db                	test   %ebx,%ebx
    a418:	0f 88 1c 03 00 00    	js     a73a <l2cap_chan_send+0xa3a>
	if (chan->fcs == L2CAP_FCS_CRC16)
    a41e:	41 80 7d 6f 01       	cmpb   $0x1,0x6f(%r13)
    a423:	0f 84 85 00 00 00    	je     a4ae <l2cap_chan_send+0x7ae>
	bt_cb(skb)->control.retries = 0;
    a429:	41 c6 46 36 00       	movb   $0x0,0x36(%r14)
	skb = chan->ops->alloc_skb(chan, count + hlen,
    a42e:	4d 89 f0             	mov    %r14,%r8
		bt_cb(skb)->control.sar = sar;
    a431:	41 0f b6 40 30       	movzbl 0x30(%r8),%eax
    a436:	0f b6 55 91          	movzbl -0x6f(%rbp),%edx
	newsk->next = next;
    a43a:	48 8d 7d b8          	lea    -0x48(%rbp),%rdi
    a43e:	c1 e2 04             	shl    $0x4,%edx
    a441:	83 e0 cf             	and    $0xffffffcf,%eax
    a444:	09 d0                	or     %edx,%eax
    a446:	41 88 40 30          	mov    %al,0x30(%r8)
	__skb_insert(newsk, next->prev, next, list);
    a44a:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
	newsk->next = next;
    a44e:	49 89 38             	mov    %rdi,(%r8)
		len -= pdu_len;
    a451:	48 8b 7d 88          	mov    -0x78(%rbp),%rdi
    a455:	48 29 7d 80          	sub    %rdi,-0x80(%rbp)
	newsk->prev = prev;
    a459:	49 89 40 08          	mov    %rax,0x8(%r8)
	next->prev  = prev->next = newsk;
    a45d:	4c 89 00             	mov    %r8,(%rax)
    a460:	48 89 f8             	mov    %rdi,%rax
	list->qlen++;
    a463:	83 45 c8 01          	addl   $0x1,-0x38(%rbp)
	next->prev  = prev->next = newsk;
    a467:	4c 89 45 c0          	mov    %r8,-0x40(%rbp)
			pdu_len += L2CAP_SDULEN_SIZE;
    a46b:	48 83 c0 02          	add    $0x2,%rax
    a46f:	66 83 7d 92 00       	cmpw   $0x0,-0x6e(%rbp)
    a474:	48 0f 44 c7          	cmove  %rdi,%rax
		if (len <= pdu_len) {
    a478:	48 39 45 80          	cmp    %rax,-0x80(%rbp)
			pdu_len += L2CAP_SDULEN_SIZE;
    a47c:	48 89 45 88          	mov    %rax,-0x78(%rbp)
		if (len <= pdu_len) {
    a480:	76 1e                	jbe    a4a0 <l2cap_chan_send+0x7a0>
			sar = L2CAP_SAR_CONTINUE;
    a482:	c6 45 91 03          	movb   $0x3,-0x6f(%rbp)
	while (len > 0) {
    a486:	48 83 7d 80 00       	cmpq   $0x0,-0x80(%rbp)
    a48b:	74 44                	je     a4d1 <l2cap_chan_send+0x7d1>
    a48d:	31 d2                	xor    %edx,%edx
    a48f:	49 8b 5d 08          	mov    0x8(%r13),%rbx
    a493:	66 89 55 92          	mov    %dx,-0x6e(%rbp)
    a497:	e9 e4 fc ff ff       	jmpq   a180 <l2cap_chan_send+0x480>
    a49c:	0f 1f 40 00          	nopl   0x0(%rax)
		if (len <= pdu_len) {
    a4a0:	48 8b 45 80          	mov    -0x80(%rbp),%rax
			sar = L2CAP_SAR_END;
    a4a4:	c6 45 91 02          	movb   $0x2,-0x6f(%rbp)
		if (len <= pdu_len) {
    a4a8:	48 89 45 88          	mov    %rax,-0x78(%rbp)
    a4ac:	eb d8                	jmp    a486 <l2cap_chan_send+0x786>
		put_unaligned_le16(0, skb_put(skb, L2CAP_FCS_SIZE));
    a4ae:	be 02 00 00 00       	mov    $0x2,%esi
    a4b3:	4c 89 f7             	mov    %r14,%rdi
    a4b6:	e8 00 00 00 00       	callq  a4bb <l2cap_chan_send+0x7bb>
    a4bb:	31 c9                	xor    %ecx,%ecx
    a4bd:	66 89 08             	mov    %cx,(%rax)
    a4c0:	e9 64 ff ff ff       	jmpq   a429 <l2cap_chan_send+0x729>
	if (!conn)
    a4c5:	c7 45 88 95 ff ff ff 	movl   $0xffffff95,-0x78(%rbp)
    a4cc:	e9 ca fe ff ff       	jmpq   a39b <l2cap_chan_send+0x69b>
		if (chan->state != BT_CONNECTED) {
    a4d1:	41 80 7d 10 01       	cmpb   $0x1,0x10(%r13)
    a4d6:	48 8b 7d b8          	mov    -0x48(%rbp),%rdi
    a4da:	0f 85 55 01 00 00    	jne    a635 <l2cap_chan_send+0x935>
		if (chan->mode == L2CAP_MODE_ERTM && chan->tx_send_head == NULL)
    a4e0:	41 0f b6 45 24       	movzbl 0x24(%r13),%eax
    a4e5:	3c 03                	cmp    $0x3,%al
    a4e7:	0f 84 f9 01 00 00    	je     a6e6 <l2cap_chan_send+0x9e6>
	if (!skb_queue_empty(list)) {
    a4ed:	48 8d 4d b8          	lea    -0x48(%rbp),%rcx
		skb_queue_splice_tail_init(&seg_queue, &chan->tx_q);
    a4f1:	4d 8d a5 b8 02 00 00 	lea    0x2b8(%r13),%r12
    a4f8:	48 39 cf             	cmp    %rcx,%rdi
    a4fb:	74 3a                	je     a537 <l2cap_chan_send+0x837>
static inline void skb_queue_splice_tail_init(struct sk_buff_head *list,
    a4fd:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
		__skb_queue_splice(list, head->prev, (struct sk_buff *) head);
    a501:	49 8b 95 c0 02 00 00 	mov    0x2c0(%r13),%rdx
	first->prev = prev;
    a508:	48 89 57 08          	mov    %rdx,0x8(%rdi)
	prev->next = first;
    a50c:	48 89 3a             	mov    %rdi,(%rdx)
	last->next = next;
    a50f:	4c 89 20             	mov    %r12,(%rax)
	next->prev = last;
    a512:	49 89 85 c0 02 00 00 	mov    %rax,0x2c0(%r13)
		head->qlen += list->qlen;
    a519:	8b 45 c8             	mov    -0x38(%rbp),%eax
    a51c:	41 01 85 c8 02 00 00 	add    %eax,0x2c8(%r13)
    a523:	41 0f b6 45 24       	movzbl 0x24(%r13),%eax
	list->prev = list->next = (struct sk_buff *)list;
    a528:	48 89 4d b8          	mov    %rcx,-0x48(%rbp)
    a52c:	48 89 4d c0          	mov    %rcx,-0x40(%rbp)
	list->qlen = 0;
    a530:	c7 45 c8 00 00 00 00 	movl   $0x0,-0x38(%rbp)
		if (chan->mode == L2CAP_MODE_ERTM)
    a537:	3c 03                	cmp    $0x3,%al
    a539:	0f 85 94 00 00 00    	jne    a5d3 <l2cap_chan_send+0x8d3>
    a53f:	e9 41 01 00 00       	jmpq   a685 <l2cap_chan_send+0x985>
    a544:	0f 1f 40 00          	nopl   0x0(%rax)
static inline u32 get_unaligned_le32(const void *p)
    a548:	8b 4a 04             	mov    0x4(%rdx),%ecx
    a54b:	49 8b b5 90 00 00 00 	mov    0x90(%r13),%rsi
		control |= __set_txseq(chan, chan->next_tx_seq);
    a552:	41 0f b7 85 98 00 00 	movzwl 0x98(%r13),%eax
    a559:	00 
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    a55a:	83 e6 10             	and    $0x10,%esi
    a55d:	0f 84 f0 00 00 00    	je     a653 <l2cap_chan_send+0x953>
		return (txseq << L2CAP_EXT_CTRL_TXSEQ_SHIFT) &
    a563:	c1 e0 12             	shl    $0x12,%eax
    a566:	09 c8                	or     %ecx,%eax
    a568:	89 c7                	mov    %eax,%edi
		control |= __set_ctrl_sar(chan, bt_cb(skb)->control.sar);
    a56a:	0f b6 43 30          	movzbl 0x30(%rbx),%eax
    a56e:	c0 e8 04             	shr    $0x4,%al
    a571:	89 c6                	mov    %eax,%esi
    a573:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
    a57a:	83 e6 03             	and    $0x3,%esi
		return (sar << L2CAP_CTRL_SAR_SHIFT) & L2CAP_CTRL_SAR;
    a57d:	89 f1                	mov    %esi,%ecx
    a57f:	c1 e1 0e             	shl    $0xe,%ecx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    a582:	a8 10                	test   $0x10,%al
    a584:	74 05                	je     a58b <l2cap_chan_send+0x88b>
		return (sar << L2CAP_EXT_CTRL_SAR_SHIFT) & L2CAP_EXT_CTRL_SAR;
    a586:	89 f1                	mov    %esi,%ecx
    a588:	c1 e1 10             	shl    $0x10,%ecx
    a58b:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
    a592:	09 f9                	or     %edi,%ecx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    a594:	a8 10                	test   $0x10,%al
    a596:	0f 84 ae 00 00 00    	je     a64a <l2cap_chan_send+0x94a>
	*((__le32 *)p) = cpu_to_le32(val);
    a59c:	89 4a 04             	mov    %ecx,0x4(%rdx)
		if (chan->fcs == L2CAP_FCS_CRC16) {
    a59f:	41 80 7d 6f 01       	cmpb   $0x1,0x6f(%r13)
    a5a4:	0f 84 b3 00 00 00    	je     a65d <l2cap_chan_send+0x95d>
		l2cap_do_send(chan, skb);
    a5aa:	48 89 de             	mov    %rbx,%rsi
    a5ad:	4c 89 ef             	mov    %r13,%rdi
    a5b0:	e8 4b 5f ff ff       	callq  500 <l2cap_do_send>
	return (seq + 1) % (chan->tx_win_max + 1);
    a5b5:	41 0f b7 85 98 00 00 	movzwl 0x98(%r13),%eax
    a5bc:	00 
    a5bd:	41 0f b7 4d 72       	movzwl 0x72(%r13),%ecx
    a5c2:	83 c0 01             	add    $0x1,%eax
    a5c5:	83 c1 01             	add    $0x1,%ecx
    a5c8:	99                   	cltd   
    a5c9:	f7 f9                	idiv   %ecx
    a5cb:	66 41 89 95 98 00 00 	mov    %dx,0x98(%r13)
    a5d2:	00 
	while ((skb = skb_dequeue(&chan->tx_q))) {
    a5d3:	4c 89 e7             	mov    %r12,%rdi
    a5d6:	e8 00 00 00 00       	callq  a5db <l2cap_chan_send+0x8db>
    a5db:	48 85 c0             	test   %rax,%rax
    a5de:	48 89 c3             	mov    %rax,%rbx
    a5e1:	0f 84 ac 00 00 00    	je     a693 <l2cap_chan_send+0x993>
    a5e7:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
		control = __get_control(chan, skb->data + L2CAP_HDR_SIZE);
    a5ee:	48 8b 93 e0 00 00 00 	mov    0xe0(%rbx),%rdx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    a5f5:	a8 10                	test   $0x10,%al
    a5f7:	0f 85 4b ff ff ff    	jne    a548 <l2cap_chan_send+0x848>
		return get_unaligned_le16(p);
    a5fd:	0f b7 4a 04          	movzwl 0x4(%rdx),%ecx
    a601:	e9 45 ff ff ff       	jmpq   a54b <l2cap_chan_send+0x84b>
	if (skb)
    a606:	48 85 ff             	test   %rdi,%rdi
    a609:	74 33                	je     a63e <l2cap_chan_send+0x93e>
	list->qlen--;
    a60b:	83 6d c8 01          	subl   $0x1,-0x38(%rbp)
	next	   = skb->next;
    a60f:	48 8b 17             	mov    (%rdi),%rdx
	prev	   = skb->prev;
    a612:	48 8b 47 08          	mov    0x8(%rdi),%rax
	skb->next  = skb->prev = NULL;
    a616:	48 c7 07 00 00 00 00 	movq   $0x0,(%rdi)
    a61d:	48 c7 47 08 00 00 00 	movq   $0x0,0x8(%rdi)
    a624:	00 
	next->prev = prev;
    a625:	48 89 42 08          	mov    %rax,0x8(%rdx)
	prev->next = next;
    a629:	48 89 10             	mov    %rdx,(%rax)
		kfree_skb(skb);
    a62c:	e8 00 00 00 00       	callq  a631 <l2cap_chan_send+0x931>
	struct sk_buff *skb = list_->next;
    a631:	48 8b 7d b8          	mov    -0x48(%rbp),%rdi
	if (skb == (struct sk_buff *)list_)
    a635:	48 8d 45 b8          	lea    -0x48(%rbp),%rax
    a639:	48 39 c7             	cmp    %rax,%rdi
    a63c:	75 c8                	jne    a606 <l2cap_chan_send+0x906>
			err = -ENOTCONN;
    a63e:	c7 45 88 95 ff ff ff 	movl   $0xffffff95,-0x78(%rbp)
    a645:	e9 2e f7 ff ff       	jmpq   9d78 <l2cap_chan_send+0x78>
    a64a:	66 89 4a 04          	mov    %cx,0x4(%rdx)
    a64e:	e9 4c ff ff ff       	jmpq   a59f <l2cap_chan_send+0x89f>
		return (txseq << L2CAP_CTRL_TXSEQ_SHIFT) & L2CAP_CTRL_TXSEQ;
    a653:	01 c0                	add    %eax,%eax
    a655:	83 e0 7e             	and    $0x7e,%eax
    a658:	e9 09 ff ff ff       	jmpq   a566 <l2cap_chan_send+0x866>
						skb->len - L2CAP_FCS_SIZE);
    a65d:	8b 43 68             	mov    0x68(%rbx),%eax
			fcs = crc16(0, (u8 *)skb->data,
    a660:	48 8b b3 e0 00 00 00 	mov    0xe0(%rbx),%rsi
    a667:	31 ff                	xor    %edi,%edi
    a669:	8d 50 fe             	lea    -0x2(%rax),%edx
    a66c:	e8 00 00 00 00       	callq  a671 <l2cap_chan_send+0x971>
					skb->data + skb->len - L2CAP_FCS_SIZE);
    a671:	8b 53 68             	mov    0x68(%rbx),%edx
	*((__le16 *)p) = cpu_to_le16(val);
    a674:	48 8b 8b e0 00 00 00 	mov    0xe0(%rbx),%rcx
    a67b:	66 89 44 11 fe       	mov    %ax,-0x2(%rcx,%rdx,1)
    a680:	e9 25 ff ff ff       	jmpq   a5aa <l2cap_chan_send+0x8aa>
			err = l2cap_ertm_send(chan);
    a685:	4c 89 ef             	mov    %r13,%rdi
    a688:	e8 c3 83 ff ff       	callq  2a50 <l2cap_ertm_send>
		if (err >= 0)
    a68d:	85 c0                	test   %eax,%eax
			err = l2cap_ertm_send(chan);
    a68f:	89 c3                	mov    %eax,%ebx
		if (err >= 0)
    a691:	78 06                	js     a699 <l2cap_chan_send+0x999>
			err = len;
    a693:	8b 9d 78 ff ff ff    	mov    -0x88(%rbp),%ebx
	struct sk_buff *skb = list_->next;
    a699:	48 8b 7d b8          	mov    -0x48(%rbp),%rdi
	if (skb == (struct sk_buff *)list_)
    a69d:	48 8d 45 b8          	lea    -0x48(%rbp),%rax
    a6a1:	48 39 c7             	cmp    %rax,%rdi
    a6a4:	74 38                	je     a6de <l2cap_chan_send+0x9de>
	if (skb)
    a6a6:	48 85 ff             	test   %rdi,%rdi
    a6a9:	74 33                	je     a6de <l2cap_chan_send+0x9de>
	list->qlen--;
    a6ab:	83 6d c8 01          	subl   $0x1,-0x38(%rbp)
	prev	   = skb->prev;
    a6af:	48 8b 47 08          	mov    0x8(%rdi),%rax
	next	   = skb->next;
    a6b3:	48 8b 17             	mov    (%rdi),%rdx
	skb->next  = skb->prev = NULL;
    a6b6:	48 c7 47 08 00 00 00 	movq   $0x0,0x8(%rdi)
    a6bd:	00 
    a6be:	48 c7 07 00 00 00 00 	movq   $0x0,(%rdi)
	next->prev = prev;
    a6c5:	48 89 42 08          	mov    %rax,0x8(%rdx)
	prev->next = next;
    a6c9:	48 89 10             	mov    %rdx,(%rax)
		kfree_skb(skb);
    a6cc:	e8 00 00 00 00       	callq  a6d1 <l2cap_chan_send+0x9d1>
	struct sk_buff *skb = list_->next;
    a6d1:	48 8b 7d b8          	mov    -0x48(%rbp),%rdi
	if (skb == (struct sk_buff *)list_)
    a6d5:	48 8d 45 b8          	lea    -0x48(%rbp),%rax
    a6d9:	48 39 c7             	cmp    %rax,%rdi
    a6dc:	75 c8                	jne    a6a6 <l2cap_chan_send+0x9a6>
	if (skb)
    a6de:	89 5d 88             	mov    %ebx,-0x78(%rbp)
    a6e1:	e9 92 f6 ff ff       	jmpq   9d78 <l2cap_chan_send+0x78>
		if (chan->mode == L2CAP_MODE_ERTM && chan->tx_send_head == NULL)
    a6e6:	49 83 bd b0 02 00 00 	cmpq   $0x0,0x2b0(%r13)
    a6ed:	00 
    a6ee:	0f 85 f9 fd ff ff    	jne    a4ed <l2cap_chan_send+0x7ed>
			chan->tx_send_head = seg_queue.next;
    a6f4:	49 89 bd b0 02 00 00 	mov    %rdi,0x2b0(%r13)
    a6fb:	e9 ed fd ff ff       	jmpq   a4ed <l2cap_chan_send+0x7ed>
    a700:	4d 89 fe             	mov    %r15,%r14
			return PTR_ERR(tmp);
    a703:	89 c3                	mov    %eax,%ebx
    a705:	e9 0c fd ff ff       	jmpq   a416 <l2cap_chan_send+0x716>
    a70a:	4d 89 e6             	mov    %r12,%r14
    a70d:	e9 34 f8 ff ff       	jmpq   9f46 <l2cap_chan_send+0x246>
	BT_DBG("chan %p len %d", chan, (int)len);
    a712:	8b 4d 88             	mov    -0x78(%rbp),%ecx
    a715:	4c 89 ea             	mov    %r13,%rdx
    a718:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    a71f:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    a726:	31 c0                	xor    %eax,%eax
    a728:	e8 00 00 00 00       	callq  a72d <l2cap_chan_send+0xa2d>
    a72d:	e9 5b fa ff ff       	jmpq   a18d <l2cap_chan_send+0x48d>
    a732:	89 45 88             	mov    %eax,-0x78(%rbp)
    a735:	e9 61 fc ff ff       	jmpq   a39b <l2cap_chan_send+0x69b>
    a73a:	48 63 db             	movslq %ebx,%rbx
		kfree_skb(skb);
    a73d:	4c 89 f7             	mov    %r14,%rdi
    a740:	e8 00 00 00 00       	callq  a745 <l2cap_chan_send+0xa45>
		if (IS_ERR(skb)) {
    a745:	48 81 fb 00 f0 ff ff 	cmp    $0xfffffffffffff000,%rbx
    a74c:	0f 87 18 fc ff ff    	ja     a36a <l2cap_chan_send+0x66a>
    a752:	49 89 d8             	mov    %rbx,%r8
    a755:	e9 d7 fc ff ff       	jmpq   a431 <l2cap_chan_send+0x731>
		return skb;
    a75a:	4d 89 f1             	mov    %r14,%r9
    a75d:	e9 d3 f7 ff ff       	jmpq   9f35 <l2cap_chan_send+0x235>
		BT_DBG("bad state %1.1x", chan->mode);
    a762:	0f b6 d0             	movzbl %al,%edx
    a765:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    a76c:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    a773:	31 c0                	xor    %eax,%eax
    a775:	e8 00 00 00 00       	callq  a77a <l2cap_chan_send+0xa7a>
		err = -EBADFD;
    a77a:	c7 45 88 b3 ff ff ff 	movl   $0xffffffb3,-0x78(%rbp)
    a781:	e9 f2 f5 ff ff       	jmpq   9d78 <l2cap_chan_send+0x78>
	BT_DBG("chan %p, msg %p, len %d", chan, msg, (int)len);
    a786:	44 8b 85 78 ff ff ff 	mov    -0x88(%rbp),%r8d
    a78d:	48 8b 4d a8          	mov    -0x58(%rbp),%rcx
    a791:	48 89 fa             	mov    %rdi,%rdx
    a794:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    a79b:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    a7a2:	31 c0                	xor    %eax,%eax
    a7a4:	e8 00 00 00 00       	callq  a7a9 <l2cap_chan_send+0xaa9>
    a7a9:	e9 6a f9 ff ff       	jmpq   a118 <l2cap_chan_send+0x418>
	BT_DBG("chan %p len %d priority %u", chan, (int)len, priority);
    a7ae:	41 89 c8             	mov    %ecx,%r8d
    a7b1:	8b 8d 78 ff ff ff    	mov    -0x88(%rbp),%ecx
    a7b7:	48 89 fa             	mov    %rdi,%rdx
    a7ba:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    a7c1:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    a7c8:	31 c0                	xor    %eax,%eax
    a7ca:	e8 00 00 00 00       	callq  a7cf <l2cap_chan_send+0xacf>
    a7cf:	e9 9b f7 ff ff       	jmpq   9f6f <l2cap_chan_send+0x26f>
    a7d4:	48 63 d8             	movslq %eax,%rbx
		kfree_skb(skb);
    a7d7:	4c 89 f7             	mov    %r14,%rdi
    a7da:	e8 00 00 00 00       	callq  a7df <l2cap_chan_send+0xadf>
		if (IS_ERR(skb))
    a7df:	48 81 fb 00 f0 ff ff 	cmp    $0xfffffffffffff000,%rbx
    a7e6:	77 2b                	ja     a813 <l2cap_chan_send+0xb13>
    a7e8:	48 89 de             	mov    %rbx,%rsi
    a7eb:	e9 61 f7 ff ff       	jmpq   9f51 <l2cap_chan_send+0x251>
	BT_DBG("chan %p len %d", chan, (int)len);
    a7f0:	8b 8d 78 ff ff ff    	mov    -0x88(%rbp),%ecx
    a7f6:	48 89 fa             	mov    %rdi,%rdx
    a7f9:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    a800:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    a807:	31 c0                	xor    %eax,%eax
    a809:	e8 00 00 00 00       	callq  a80e <l2cap_chan_send+0xb0e>
    a80e:	e9 a2 f5 ff ff       	jmpq   9db5 <l2cap_chan_send+0xb5>
    a813:	49 89 d9             	mov    %rbx,%r9
    a816:	e9 1a f7 ff ff       	jmpq   9f35 <l2cap_chan_send+0x235>
    a81b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

000000000000a820 <__l2cap_connect_rsp_defer>:
{
    a820:	55                   	push   %rbp
    a821:	48 89 e5             	mov    %rsp,%rbp
    a824:	41 55                	push   %r13
    a826:	41 54                	push   %r12
    a828:	53                   	push   %rbx
    a829:	48 81 ec 98 00 00 00 	sub    $0x98,%rsp
    a830:	e8 00 00 00 00       	callq  a835 <__l2cap_connect_rsp_defer+0x15>
	struct l2cap_conn *conn = chan->conn;
    a835:	4c 8b 67 08          	mov    0x8(%rdi),%r12
	l2cap_send_cmd(conn, chan->ident,
    a839:	0f b6 77 2b          	movzbl 0x2b(%rdi),%esi
	rsp.status = cpu_to_le16(L2CAP_CS_NO_INFO);
    a83d:	31 d2                	xor    %edx,%edx
{
    a83f:	65 48 8b 04 25 28 00 	mov    %gs:0x28,%rax
    a846:	00 00 
    a848:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    a84c:	31 c0                	xor    %eax,%eax
	rsp.scid   = cpu_to_le16(chan->dcid);
    a84e:	0f b7 47 1a          	movzwl 0x1a(%rdi),%eax
	l2cap_send_cmd(conn, chan->ident,
    a852:	4c 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%r8
	rsp.status = cpu_to_le16(L2CAP_CS_NO_INFO);
    a859:	66 89 95 56 ff ff ff 	mov    %dx,-0xaa(%rbp)
{
    a860:	48 89 fb             	mov    %rdi,%rbx
	l2cap_send_cmd(conn, chan->ident,
    a863:	b9 08 00 00 00       	mov    $0x8,%ecx
    a868:	ba 03 00 00 00       	mov    $0x3,%edx
	rsp.scid   = cpu_to_le16(chan->dcid);
    a86d:	66 89 85 52 ff ff ff 	mov    %ax,-0xae(%rbp)
	rsp.dcid   = cpu_to_le16(chan->scid);
    a874:	0f b7 47 1c          	movzwl 0x1c(%rdi),%eax
	l2cap_send_cmd(conn, chan->ident,
    a878:	4c 89 e7             	mov    %r12,%rdi
	rsp.dcid   = cpu_to_le16(chan->scid);
    a87b:	66 89 85 50 ff ff ff 	mov    %ax,-0xb0(%rbp)
	rsp.result = cpu_to_le16(L2CAP_CR_SUCCESS);
    a882:	31 c0                	xor    %eax,%eax
    a884:	66 89 85 54 ff ff ff 	mov    %ax,-0xac(%rbp)
	l2cap_send_cmd(conn, chan->ident,
    a88b:	e8 30 6b ff ff       	callq  13c0 <l2cap_send_cmd>
	asm volatile(LOCK_PREFIX "bts %2,%1\n\t"
    a890:	f0 0f ba ab 80 00 00 	lock btsl $0x0,0x80(%rbx)
    a897:	00 00 
    a899:	19 c0                	sbb    %eax,%eax
	if (test_and_set_bit(CONF_REQ_SENT, &chan->conf_state))
    a89b:	85 c0                	test   %eax,%eax
    a89d:	74 21                	je     a8c0 <__l2cap_connect_rsp_defer+0xa0>
}
    a89f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    a8a3:	65 48 33 04 25 28 00 	xor    %gs:0x28,%rax
    a8aa:	00 00 
    a8ac:	75 4d                	jne    a8fb <__l2cap_connect_rsp_defer+0xdb>
    a8ae:	48 81 c4 98 00 00 00 	add    $0x98,%rsp
    a8b5:	5b                   	pop    %rbx
    a8b6:	41 5c                	pop    %r12
    a8b8:	41 5d                	pop    %r13
    a8ba:	5d                   	pop    %rbp
    a8bb:	c3                   	retq   
    a8bc:	0f 1f 40 00          	nopl   0x0(%rax)
			l2cap_build_conf_req(chan, buf), buf);
    a8c0:	48 8d b5 58 ff ff ff 	lea    -0xa8(%rbp),%rsi
    a8c7:	48 89 df             	mov    %rbx,%rdi
    a8ca:	e8 a1 6d ff ff       	callq  1670 <l2cap_build_conf_req>
	l2cap_send_cmd(conn, l2cap_get_ident(conn), L2CAP_CONF_REQ,
    a8cf:	4c 89 e7             	mov    %r12,%rdi
			l2cap_build_conf_req(chan, buf), buf);
    a8d2:	41 89 c5             	mov    %eax,%r13d
	l2cap_send_cmd(conn, l2cap_get_ident(conn), L2CAP_CONF_REQ,
    a8d5:	e8 d6 5b ff ff       	callq  4b0 <l2cap_get_ident>
    a8da:	4c 8d 85 58 ff ff ff 	lea    -0xa8(%rbp),%r8
    a8e1:	41 0f b7 cd          	movzwl %r13w,%ecx
    a8e5:	0f b6 f0             	movzbl %al,%esi
    a8e8:	ba 04 00 00 00       	mov    $0x4,%edx
    a8ed:	4c 89 e7             	mov    %r12,%rdi
    a8f0:	e8 cb 6a ff ff       	callq  13c0 <l2cap_send_cmd>
	chan->num_conf_req++;
    a8f5:	80 43 6d 01          	addb   $0x1,0x6d(%rbx)
    a8f9:	eb a4                	jmp    a89f <__l2cap_connect_rsp_defer+0x7f>
}
    a8fb:	e8 00 00 00 00       	callq  a900 <l2cap_chan_busy>

000000000000a900 <l2cap_chan_busy>:
{
    a900:	55                   	push   %rbp
    a901:	48 89 e5             	mov    %rsp,%rbp
    a904:	41 57                	push   %r15
    a906:	41 56                	push   %r14
    a908:	41 55                	push   %r13
    a90a:	41 54                	push   %r12
    a90c:	53                   	push   %rbx
    a90d:	48 83 ec 18          	sub    $0x18,%rsp
    a911:	e8 00 00 00 00       	callq  a916 <l2cap_chan_busy+0x16>
	if (chan->mode == L2CAP_MODE_ERTM) {
    a916:	80 7f 24 03          	cmpb   $0x3,0x24(%rdi)
{
    a91a:	48 89 fb             	mov    %rdi,%rbx
	if (chan->mode == L2CAP_MODE_ERTM) {
    a91d:	74 11                	je     a930 <l2cap_chan_busy+0x30>
}
    a91f:	48 83 c4 18          	add    $0x18,%rsp
    a923:	5b                   	pop    %rbx
    a924:	41 5c                	pop    %r12
    a926:	41 5d                	pop    %r13
    a928:	41 5e                	pop    %r14
    a92a:	41 5f                	pop    %r15
    a92c:	5d                   	pop    %rbp
    a92d:	c3                   	retq   
    a92e:	66 90                	xchg   %ax,%ax
		if (busy)
    a930:	85 f6                	test   %esi,%esi
    a932:	0f 85 28 01 00 00    	jne    aa60 <l2cap_chan_busy+0x160>
		(addr[nr / BITS_PER_LONG])) != 0;
    a938:	48 8b 87 88 00 00 00 	mov    0x88(%rdi),%rax
    a93f:	4c 8d a7 88 00 00 00 	lea    0x88(%rdi),%r12
	if (!test_bit(CONN_RNR_SENT, &chan->conn_state))
    a946:	f6 c4 01             	test   $0x1,%ah
    a949:	0f 84 d8 00 00 00    	je     aa27 <l2cap_chan_busy+0x127>
    a94f:	48 8b 87 90 00 00 00 	mov    0x90(%rdi),%rax
	control = __set_reqseq(chan, chan->buffer_seq);
    a956:	44 0f b7 b7 9e 00 00 	movzwl 0x9e(%rdi),%r14d
    a95d:	00 
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    a95e:	a8 10                	test   $0x10,%al
    a960:	0f 84 b2 01 00 00    	je     ab18 <l2cap_chan_busy+0x218>
		return (reqseq << L2CAP_EXT_CTRL_REQSEQ_SHIFT) &
    a966:	41 c1 e6 02          	shl    $0x2,%r14d
    a96a:	45 0f b7 f6          	movzwl %r14w,%r14d
    a96e:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
	struct l2cap_conn *conn = chan->conn;
    a975:	4c 8b 63 08          	mov    0x8(%rbx),%r12
    a979:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
    a980:	48 c1 e8 04          	shr    $0x4,%rax
    a984:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_POLL;
    a987:	48 83 f8 01          	cmp    $0x1,%rax
    a98b:	19 c0                	sbb    %eax,%eax
    a98d:	25 10 00 fc ff       	and    $0xfffc0010,%eax
    a992:	05 00 00 04 00       	add    $0x40000,%eax
	if (chan->state != BT_CONNECTED)
    a997:	80 7b 10 01          	cmpb   $0x1,0x10(%rbx)
    a99b:	0f 84 bf 01 00 00    	je     ab60 <l2cap_chan_busy+0x260>
    a9a1:	4c 8d ab 88 00 00 00 	lea    0x88(%rbx),%r13
    a9a8:	4d 89 ec             	mov    %r13,%r12
	ret = del_timer_sync(&work->timer);
    a9ab:	48 8d bb 80 01 00 00 	lea    0x180(%rbx),%rdi
	chan->retry_count = 1;
    a9b2:	c6 83 aa 00 00 00 01 	movb   $0x1,0xaa(%rbx)
    a9b9:	e8 00 00 00 00       	callq  a9be <l2cap_chan_busy+0xbe>
	if (ret)
    a9be:	85 c0                	test   %eax,%eax
    a9c0:	74 17                	je     a9d9 <l2cap_chan_busy+0xd9>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    a9c2:	f0 80 a3 60 01 00 00 	lock andb $0xfe,0x160(%rbx)
    a9c9:	fe 
    a9ca:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    a9ce:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    a9d1:	84 c0                	test   %al,%al
    a9d3:	0f 85 67 01 00 00    	jne    ab40 <l2cap_chan_busy+0x240>
	__set_monitor_timer(chan);
    a9d9:	bf e0 2e 00 00       	mov    $0x2ee0,%edi
    a9de:	4c 8d bb d0 01 00 00 	lea    0x1d0(%rbx),%r15
    a9e5:	e8 00 00 00 00       	callq  a9ea <l2cap_chan_busy+0xea>
	BT_DBG("chan %p state %s timeout %ld", chan,
    a9ea:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # a9f1 <l2cap_chan_busy+0xf1>
    a9f1:	49 89 c6             	mov    %rax,%r14
    a9f4:	0f 85 85 03 00 00    	jne    ad7f <l2cap_chan_busy+0x47f>
	ret = del_timer_sync(&work->timer);
    a9fa:	48 8d bb f0 01 00 00 	lea    0x1f0(%rbx),%rdi
    aa01:	e8 00 00 00 00       	callq  aa06 <l2cap_chan_busy+0x106>
	if (ret)
    aa06:	85 c0                	test   %eax,%eax
    aa08:	0f 84 42 01 00 00    	je     ab50 <l2cap_chan_busy+0x250>
    aa0e:	f0 80 a3 d0 01 00 00 	lock andb $0xfe,0x1d0(%rbx)
    aa15:	fe 
	schedule_delayed_work(work, timeout);
    aa16:	4c 89 f6             	mov    %r14,%rsi
    aa19:	4c 89 ff             	mov    %r15,%rdi
    aa1c:	e8 00 00 00 00       	callq  aa21 <l2cap_chan_busy+0x121>
		asm volatile(LOCK_PREFIX "orb %1,%0"
    aa21:	f0 41 80 4d 00 02    	lock orb $0x2,0x0(%r13)
		asm volatile(LOCK_PREFIX "andb %1,%0"
    aa27:	f0 41 80 24 24 df    	lock andb $0xdf,(%r12)
    aa2d:	f0 80 a3 89 00 00 00 	lock andb $0xfe,0x89(%rbx)
    aa34:	fe 
	BT_DBG("chan %p, Exit local busy", chan);
    aa35:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # aa3c <l2cap_chan_busy+0x13c>
    aa3c:	0f 84 dd fe ff ff    	je     a91f <l2cap_chan_busy+0x1f>
    aa42:	48 89 da             	mov    %rbx,%rdx
    aa45:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    aa4c:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    aa53:	31 c0                	xor    %eax,%eax
    aa55:	e8 00 00 00 00       	callq  aa5a <l2cap_chan_busy+0x15a>
    aa5a:	e9 c0 fe ff ff       	jmpq   a91f <l2cap_chan_busy+0x1f>
    aa5f:	90                   	nop
	BT_DBG("chan %p, Enter local busy", chan);
    aa60:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # aa67 <l2cap_chan_busy+0x167>
    aa67:	0f 85 f5 02 00 00    	jne    ad62 <l2cap_chan_busy+0x462>
		asm volatile(LOCK_PREFIX "orb %1,%0"
    aa6d:	f0 80 8b 88 00 00 00 	lock orb $0x20,0x88(%rbx)
    aa74:	20 
	if (seq_list->head == L2CAP_SEQ_LIST_CLEAR)
    aa75:	66 83 bb e8 02 00 00 	cmpw   $0xffff,0x2e8(%rbx)
    aa7c:	ff 
    aa7d:	74 40                	je     aabf <l2cap_chan_busy+0x1bf>
    aa7f:	31 c0                	xor    %eax,%eax
    aa81:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		seq_list->list[i] = L2CAP_SEQ_LIST_CLEAR;
    aa88:	48 8b 93 f0 02 00 00 	mov    0x2f0(%rbx),%rdx
    aa8f:	0f b7 c8             	movzwl %ax,%ecx
    aa92:	be ff ff ff ff       	mov    $0xffffffff,%esi
	for (i = 0; i <= seq_list->mask; i++)
    aa97:	83 c0 01             	add    $0x1,%eax
		seq_list->list[i] = L2CAP_SEQ_LIST_CLEAR;
    aa9a:	66 89 34 4a          	mov    %si,(%rdx,%rcx,2)
	for (i = 0; i <= seq_list->mask; i++)
    aa9e:	66 3b 83 ec 02 00 00 	cmp    0x2ec(%rbx),%ax
    aaa5:	76 e1                	jbe    aa88 <l2cap_chan_busy+0x188>
	seq_list->head = L2CAP_SEQ_LIST_CLEAR;
    aaa7:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
	seq_list->tail = L2CAP_SEQ_LIST_CLEAR;
    aaac:	ba ff ff ff ff       	mov    $0xffffffff,%edx
	seq_list->head = L2CAP_SEQ_LIST_CLEAR;
    aab1:	66 89 83 e8 02 00 00 	mov    %ax,0x2e8(%rbx)
	seq_list->tail = L2CAP_SEQ_LIST_CLEAR;
    aab8:	66 89 93 ea 02 00 00 	mov    %dx,0x2ea(%rbx)
	__set_ack_timer(chan);
    aabf:	bf c8 00 00 00       	mov    $0xc8,%edi
    aac4:	4c 8d ab 40 02 00 00 	lea    0x240(%rbx),%r13
    aacb:	e8 00 00 00 00       	callq  aad0 <l2cap_chan_busy+0x1d0>
	BT_DBG("chan %p state %s timeout %ld", chan,
    aad0:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # aad7 <l2cap_chan_busy+0x1d7>
    aad7:	49 89 c4             	mov    %rax,%r12
    aada:	0f 85 47 02 00 00    	jne    ad27 <l2cap_chan_busy+0x427>
	ret = del_timer_sync(&work->timer);
    aae0:	48 8d bb 60 02 00 00 	lea    0x260(%rbx),%rdi
    aae7:	e8 00 00 00 00       	callq  aaec <l2cap_chan_busy+0x1ec>
	if (ret)
    aaec:	85 c0                	test   %eax,%eax
    aaee:	74 40                	je     ab30 <l2cap_chan_busy+0x230>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    aaf0:	f0 80 a3 40 02 00 00 	lock andb $0xfe,0x240(%rbx)
    aaf7:	fe 
	schedule_delayed_work(work, timeout);
    aaf8:	4c 89 e6             	mov    %r12,%rsi
    aafb:	4c 89 ef             	mov    %r13,%rdi
    aafe:	e8 00 00 00 00       	callq  ab03 <l2cap_chan_busy+0x203>
}
    ab03:	48 83 c4 18          	add    $0x18,%rsp
    ab07:	5b                   	pop    %rbx
    ab08:	41 5c                	pop    %r12
    ab0a:	41 5d                	pop    %r13
    ab0c:	41 5e                	pop    %r14
    ab0e:	41 5f                	pop    %r15
    ab10:	5d                   	pop    %rbp
    ab11:	c3                   	retq   
    ab12:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		return (reqseq << L2CAP_CTRL_REQSEQ_SHIFT) & L2CAP_CTRL_REQSEQ;
    ab18:	41 c1 e6 08          	shl    $0x8,%r14d
    ab1c:	41 81 e6 00 3f 00 00 	and    $0x3f00,%r14d
    ab23:	e9 46 fe ff ff       	jmpq   a96e <l2cap_chan_busy+0x6e>
    ab28:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    ab2f:	00 
	asm volatile(LOCK_PREFIX "incl %0"
    ab30:	f0 ff 43 14          	lock incl 0x14(%rbx)
    ab34:	eb c2                	jmp    aaf8 <l2cap_chan_busy+0x1f8>
    ab36:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    ab3d:	00 00 00 
		kfree(c);
    ab40:	48 89 df             	mov    %rbx,%rdi
    ab43:	e8 00 00 00 00       	callq  ab48 <l2cap_chan_busy+0x248>
    ab48:	e9 8c fe ff ff       	jmpq   a9d9 <l2cap_chan_busy+0xd9>
    ab4d:	0f 1f 00             	nopl   (%rax)
    ab50:	f0 ff 43 14          	lock incl 0x14(%rbx)
    ab54:	e9 bd fe ff ff       	jmpq   aa16 <l2cap_chan_busy+0x116>
    ab59:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		(addr[nr / BITS_PER_LONG])) != 0;
    ab60:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
    ab67:	48 c1 ea 04          	shr    $0x4,%rdx
    ab6b:	83 e2 01             	and    $0x1,%edx
		hlen = L2CAP_EXT_HDR_SIZE;
    ab6e:	48 83 fa 01          	cmp    $0x1,%rdx
    ab72:	45 19 c0             	sbb    %r8d,%r8d
    ab75:	41 83 e0 fe          	and    $0xfffffffe,%r8d
    ab79:	41 83 c0 08          	add    $0x8,%r8d
		hlen += L2CAP_FCS_SIZE;
    ab7d:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    ab81:	41 8d 50 02          	lea    0x2(%r8),%edx
    ab85:	44 0f 44 c2          	cmove  %edx,%r8d
	control |= __set_ctrl_poll(chan);
    ab89:	41 09 c6             	or     %eax,%r14d
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    ab8c:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # ab93 <l2cap_chan_busy+0x293>
    ab93:	0f 85 66 01 00 00    	jne    acff <l2cap_chan_busy+0x3ff>
	count = min_t(unsigned int, conn->mtu, hlen);
    ab99:	45 8b 7c 24 20       	mov    0x20(%r12),%r15d
	if (test_and_clear_bit(CONN_SEND_FBIT, &chan->conn_state))
    ab9e:	4c 8d ab 88 00 00 00 	lea    0x88(%rbx),%r13
    aba5:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    abac:	4d 89 ec             	mov    %r13,%r12
	count = min_t(unsigned int, conn->mtu, hlen);
    abaf:	45 39 f8             	cmp    %r15d,%r8d
    abb2:	45 0f 46 f8          	cmovbe %r8d,%r15d
	control |= __set_sframe(chan);
    abb6:	41 83 ce 01          	or     $0x1,%r14d
	count = min_t(unsigned int, conn->mtu, hlen);
    abba:	44 89 7d cc          	mov    %r15d,-0x34(%rbp)
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    abbe:	f0 0f ba b3 88 00 00 	lock btrl $0x7,0x88(%rbx)
    abc5:	00 07 
    abc7:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_FBIT, &chan->conn_state))
    abc9:	85 c0                	test   %eax,%eax
    abcb:	74 1d                	je     abea <l2cap_chan_busy+0x2ea>
		(addr[nr / BITS_PER_LONG])) != 0;
    abcd:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    abd4:	48 c1 e8 04          	shr    $0x4,%rax
    abd8:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_FINAL;
    abdb:	48 83 f8 01          	cmp    $0x1,%rax
    abdf:	19 c0                	sbb    %eax,%eax
    abe1:	83 e0 7e             	and    $0x7e,%eax
    abe4:	83 c0 02             	add    $0x2,%eax
		control |= __set_ctrl_final(chan);
    abe7:	41 09 c6             	or     %eax,%r14d
	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
    abea:	f0 0f ba b3 88 00 00 	lock btrl $0x3,0x88(%rbx)
    abf1:	00 03 
    abf3:	19 c0                	sbb    %eax,%eax
	if (test_and_clear_bit(CONN_SEND_PBIT, &chan->conn_state))
    abf5:	85 c0                	test   %eax,%eax
    abf7:	74 21                	je     ac1a <l2cap_chan_busy+0x31a>
		(addr[nr / BITS_PER_LONG])) != 0;
    abf9:	48 8b 83 90 00 00 00 	mov    0x90(%rbx),%rax
    ac00:	48 c1 e8 04          	shr    $0x4,%rax
    ac04:	83 e0 01             	and    $0x1,%eax
		return L2CAP_EXT_CTRL_POLL;
    ac07:	48 83 f8 01          	cmp    $0x1,%rax
    ac0b:	19 c0                	sbb    %eax,%eax
    ac0d:	25 10 00 fc ff       	and    $0xfffc0010,%eax
    ac12:	05 00 00 04 00       	add    $0x40000,%eax
		control |= __set_ctrl_poll(chan);
    ac17:	41 09 c6             	or     %eax,%r14d
	if ((skb = alloc_skb(len + BT_SKB_RESERVE, how))) {
    ac1a:	8b 45 cc             	mov    -0x34(%rbp),%eax
	return __alloc_skb(size, priority, 0, NUMA_NO_NODE);
    ac1d:	31 d2                	xor    %edx,%edx
    ac1f:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    ac24:	be 20 00 00 00       	mov    $0x20,%esi
    ac29:	44 89 45 c0          	mov    %r8d,-0x40(%rbp)
    ac2d:	8d 78 08             	lea    0x8(%rax),%edi
    ac30:	e8 00 00 00 00       	callq  ac35 <l2cap_chan_busy+0x335>
    ac35:	48 85 c0             	test   %rax,%rax
    ac38:	49 89 c7             	mov    %rax,%r15
    ac3b:	0f 84 67 fd ff ff    	je     a9a8 <l2cap_chan_busy+0xa8>
	skb->data += len;
    ac41:	48 83 80 e0 00 00 00 	addq   $0x8,0xe0(%rax)
    ac48:	08 
	skb->tail += len;
    ac49:	83 80 cc 00 00 00 08 	addl   $0x8,0xcc(%rax)
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    ac50:	be 04 00 00 00       	mov    $0x4,%esi
    ac55:	48 89 c7             	mov    %rax,%rdi
		bt_cb(skb)->incoming  = 0;
    ac58:	c6 40 29 00          	movb   $0x0,0x29(%rax)
    ac5c:	e8 00 00 00 00       	callq  ac61 <l2cap_chan_busy+0x361>
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    ac61:	44 8b 45 c0          	mov    -0x40(%rbp),%r8d
	lh = (struct l2cap_hdr *) skb_put(skb, L2CAP_HDR_SIZE);
    ac65:	49 89 c1             	mov    %rax,%r9
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    ac68:	4c 89 ff             	mov    %r15,%rdi
	lh->cid = cpu_to_le16(chan->dcid);
    ac6b:	4c 89 4d c0          	mov    %r9,-0x40(%rbp)
	lh->len = cpu_to_le16(hlen - L2CAP_HDR_SIZE);
    ac6f:	41 83 e8 04          	sub    $0x4,%r8d
    ac73:	66 44 89 00          	mov    %r8w,(%rax)
	lh->cid = cpu_to_le16(chan->dcid);
    ac77:	0f b7 43 1a          	movzwl 0x1a(%rbx),%eax
    ac7b:	66 41 89 41 02       	mov    %ax,0x2(%r9)
    ac80:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
    ac87:	48 c1 ea 04          	shr    $0x4,%rdx
    ac8b:	83 e2 01             	and    $0x1,%edx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    ac8e:	48 83 fa 01          	cmp    $0x1,%rdx
    ac92:	19 f6                	sbb    %esi,%esi
    ac94:	83 e6 fe             	and    $0xfffffffe,%esi
    ac97:	83 c6 04             	add    $0x4,%esi
	__put_control(chan, control, skb_put(skb, __ctrl_size(chan)));
    ac9a:	e8 00 00 00 00       	callq  ac9f <l2cap_chan_busy+0x39f>
    ac9f:	48 8b 93 90 00 00 00 	mov    0x90(%rbx),%rdx
	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
    aca6:	4c 8b 4d c0          	mov    -0x40(%rbp),%r9
    acaa:	83 e2 10             	and    $0x10,%edx
    acad:	74 21                	je     acd0 <l2cap_chan_busy+0x3d0>
	*((__le32 *)p) = cpu_to_le32(val);
    acaf:	44 89 30             	mov    %r14d,(%rax)
	if (chan->fcs == L2CAP_FCS_CRC16) {
    acb2:	80 7b 6f 01          	cmpb   $0x1,0x6f(%rbx)
    acb6:	74 1e                	je     acd6 <l2cap_chan_busy+0x3d6>
	skb->priority = HCI_PRIO_MAX;
    acb8:	41 c7 47 78 07 00 00 	movl   $0x7,0x78(%r15)
    acbf:	00 
	l2cap_do_send(chan, skb);
    acc0:	4c 89 fe             	mov    %r15,%rsi
    acc3:	48 89 df             	mov    %rbx,%rdi
    acc6:	e8 35 58 ff ff       	callq  500 <l2cap_do_send>
    accb:	e9 db fc ff ff       	jmpq   a9ab <l2cap_chan_busy+0xab>
    acd0:	66 44 89 30          	mov    %r14w,(%rax)
    acd4:	eb dc                	jmp    acb2 <l2cap_chan_busy+0x3b2>
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    acd6:	8b 55 cc             	mov    -0x34(%rbp),%edx
    acd9:	4c 89 ce             	mov    %r9,%rsi
    acdc:	31 ff                	xor    %edi,%edi
    acde:	83 ea 02             	sub    $0x2,%edx
    ace1:	48 63 d2             	movslq %edx,%rdx
    ace4:	e8 00 00 00 00       	callq  ace9 <l2cap_chan_busy+0x3e9>
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    ace9:	be 02 00 00 00       	mov    $0x2,%esi
		u16 fcs = crc16(0, (u8 *)lh, count - L2CAP_FCS_SIZE);
    acee:	41 89 c6             	mov    %eax,%r14d
		put_unaligned_le16(fcs, skb_put(skb, L2CAP_FCS_SIZE));
    acf1:	4c 89 ff             	mov    %r15,%rdi
    acf4:	e8 00 00 00 00       	callq  acf9 <l2cap_chan_busy+0x3f9>
	*((__le16 *)p) = cpu_to_le16(val);
    acf9:	66 44 89 30          	mov    %r14w,(%rax)
    acfd:	eb b9                	jmp    acb8 <l2cap_chan_busy+0x3b8>
	BT_DBG("chan %p, control 0x%8.8x", chan, control);
    acff:	44 89 f1             	mov    %r14d,%ecx
    ad02:	48 89 da             	mov    %rbx,%rdx
    ad05:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    ad0c:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    ad13:	31 c0                	xor    %eax,%eax
    ad15:	44 89 45 cc          	mov    %r8d,-0x34(%rbp)
    ad19:	e8 00 00 00 00       	callq  ad1e <l2cap_chan_busy+0x41e>
    ad1e:	44 8b 45 cc          	mov    -0x34(%rbp),%r8d
    ad22:	e9 72 fe ff ff       	jmpq   ab99 <l2cap_chan_busy+0x299>
	switch (state) {
    ad27:	0f b6 43 10          	movzbl 0x10(%rbx),%eax
    ad2b:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    ad32:	83 e8 01             	sub    $0x1,%eax
    ad35:	83 f8 08             	cmp    $0x8,%eax
    ad38:	77 08                	ja     ad42 <l2cap_chan_busy+0x442>
    ad3a:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    ad41:	00 
	BT_DBG("chan %p state %s timeout %ld", chan,
    ad42:	4d 89 e0             	mov    %r12,%r8
    ad45:	48 89 da             	mov    %rbx,%rdx
    ad48:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    ad4f:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    ad56:	31 c0                	xor    %eax,%eax
    ad58:	e8 00 00 00 00       	callq  ad5d <l2cap_chan_busy+0x45d>
    ad5d:	e9 7e fd ff ff       	jmpq   aae0 <l2cap_chan_busy+0x1e0>
	BT_DBG("chan %p, Enter local busy", chan);
    ad62:	48 89 fa             	mov    %rdi,%rdx
    ad65:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    ad6c:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    ad73:	31 c0                	xor    %eax,%eax
    ad75:	e8 00 00 00 00       	callq  ad7a <l2cap_chan_busy+0x47a>
    ad7a:	e9 ee fc ff ff       	jmpq   aa6d <l2cap_chan_busy+0x16d>
    ad7f:	0f b6 43 10          	movzbl 0x10(%rbx),%eax
    ad83:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    ad8a:	83 e8 01             	sub    $0x1,%eax
    ad8d:	83 f8 08             	cmp    $0x8,%eax
    ad90:	77 08                	ja     ad9a <l2cap_chan_busy+0x49a>
    ad92:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    ad99:	00 
    ad9a:	4d 89 f0             	mov    %r14,%r8
    ad9d:	48 89 da             	mov    %rbx,%rdx
    ada0:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    ada7:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    adae:	31 c0                	xor    %eax,%eax
    adb0:	e8 00 00 00 00       	callq  adb5 <l2cap_chan_busy+0x4b5>
    adb5:	e9 40 fc ff ff       	jmpq   a9fa <l2cap_chan_busy+0xfa>
    adba:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

000000000000adc0 <l2cap_connect_ind>:
{
    adc0:	55                   	push   %rbp
    adc1:	48 89 e5             	mov    %rsp,%rbp
    adc4:	41 57                	push   %r15
    adc6:	41 56                	push   %r14
    adc8:	41 55                	push   %r13
    adca:	41 54                	push   %r12
    adcc:	53                   	push   %rbx
    adcd:	48 83 ec 28          	sub    $0x28,%rsp
    add1:	e8 00 00 00 00       	callq  add6 <l2cap_connect_ind+0x16>
	BT_DBG("hdev %s, bdaddr %s", hdev->name, batostr(bdaddr));
    add6:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # addd <l2cap_connect_ind+0x1d>
{
    addd:	49 89 fe             	mov    %rdi,%r14
	BT_DBG("hdev %s, bdaddr %s", hdev->name, batostr(bdaddr));
    ade0:	0f 85 0c 01 00 00    	jne    aef2 <l2cap_connect_ind+0x132>
	read_lock(&chan_list_lock);
    ade6:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
	int exact = 0, lm1 = 0, lm2 = 0;
    aded:	45 31 ff             	xor    %r15d,%r15d
    adf0:	45 31 e4             	xor    %r12d,%r12d
	read_lock(&chan_list_lock);
    adf3:	e8 00 00 00 00       	callq  adf8 <l2cap_connect_ind+0x38>
	list_for_each_entry(c, &chan_list, global_l) {
    adf8:	48 8b 05 00 00 00 00 	mov    0x0(%rip),%rax        # adff <l2cap_connect_ind+0x3f>
	int exact = 0, lm1 = 0, lm2 = 0;
    adff:	c7 45 bc 00 00 00 00 	movl   $0x0,-0x44(%rbp)
	list_for_each_entry(c, &chan_list, global_l) {
    ae06:	48 3d 00 00 00 00    	cmp    $0x0,%rax
    ae0c:	4c 8d a8 d8 fc ff ff 	lea    -0x328(%rax),%r13
    ae13:	0f 84 b7 00 00 00    	je     aed0 <l2cap_connect_ind+0x110>
	return memcmp(ba1, ba2, sizeof(bdaddr_t));
    ae19:	49 83 c6 44          	add    $0x44,%r14
    ae1d:	eb 1b                	jmp    ae3a <l2cap_connect_ind+0x7a>
    ae1f:	90                   	nop
    ae20:	49 8b 85 28 03 00 00 	mov    0x328(%r13),%rax
    ae27:	48 3d 00 00 00 00    	cmp    $0x0,%rax
    ae2d:	4c 8d a8 d8 fc ff ff 	lea    -0x328(%rax),%r13
    ae34:	0f 84 96 00 00 00    	je     aed0 <l2cap_connect_ind+0x110>
		if (c->state != BT_LISTEN)
    ae3a:	41 80 7d 10 04       	cmpb   $0x4,0x10(%r13)
		struct sock *sk = c->sk;
    ae3f:	49 8b 5d 00          	mov    0x0(%r13),%rbx
		if (c->state != BT_LISTEN)
    ae43:	75 db                	jne    ae20 <l2cap_connect_ind+0x60>
		if (!bacmp(&bt_sk(sk)->src, &hdev->bdaddr)) {
    ae45:	48 81 c3 88 02 00 00 	add    $0x288,%rbx
    ae4c:	ba 06 00 00 00       	mov    $0x6,%edx
    ae51:	4c 89 f6             	mov    %r14,%rsi
    ae54:	48 89 df             	mov    %rbx,%rdi
    ae57:	e8 00 00 00 00       	callq  ae5c <l2cap_connect_ind+0x9c>
    ae5c:	85 c0                	test   %eax,%eax
    ae5e:	75 20                	jne    ae80 <l2cap_connect_ind+0xc0>
    ae60:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
			lm1 |= HCI_LM_ACCEPT;
    ae67:	41 81 cc 00 80 00 00 	or     $0x8000,%r12d
    ae6e:	a8 01                	test   $0x1,%al
    ae70:	b8 01 80 00 00       	mov    $0x8001,%eax
    ae75:	44 0f 45 e0          	cmovne %eax,%r12d
			exact++;
    ae79:	83 45 bc 01          	addl   $0x1,-0x44(%rbp)
    ae7d:	eb a1                	jmp    ae20 <l2cap_connect_ind+0x60>
    ae7f:	90                   	nop
    ae80:	48 8d 75 ca          	lea    -0x36(%rbp),%rsi
    ae84:	ba 06 00 00 00       	mov    $0x6,%edx
    ae89:	48 89 df             	mov    %rbx,%rdi
		} else if (!bacmp(&bt_sk(sk)->src, BDADDR_ANY)) {
    ae8c:	c6 45 ca 00          	movb   $0x0,-0x36(%rbp)
    ae90:	c6 45 cb 00          	movb   $0x0,-0x35(%rbp)
    ae94:	c6 45 cc 00          	movb   $0x0,-0x34(%rbp)
    ae98:	c6 45 cd 00          	movb   $0x0,-0x33(%rbp)
    ae9c:	c6 45 ce 00          	movb   $0x0,-0x32(%rbp)
    aea0:	c6 45 cf 00          	movb   $0x0,-0x31(%rbp)
    aea4:	e8 00 00 00 00       	callq  aea9 <l2cap_connect_ind+0xe9>
    aea9:	85 c0                	test   %eax,%eax
    aeab:	0f 85 6f ff ff ff    	jne    ae20 <l2cap_connect_ind+0x60>
    aeb1:	49 8b 85 90 00 00 00 	mov    0x90(%r13),%rax
			lm2 |= HCI_LM_ACCEPT;
    aeb8:	41 81 cf 00 80 00 00 	or     $0x8000,%r15d
    aebf:	a8 01                	test   $0x1,%al
    aec1:	b8 01 80 00 00       	mov    $0x8001,%eax
    aec6:	44 0f 45 f8          	cmovne %eax,%r15d
    aeca:	e9 51 ff ff ff       	jmpq   ae20 <l2cap_connect_ind+0x60>
    aecf:	90                   	nop
	asm volatile(LOCK_PREFIX READ_LOCK_SIZE(inc) " %0"
    aed0:	f0 ff 05 00 00 00 00 	lock incl 0x0(%rip)        # aed7 <l2cap_connect_ind+0x117>
	return exact ? lm1 : lm2;
    aed7:	8b 45 bc             	mov    -0x44(%rbp),%eax
    aeda:	85 c0                	test   %eax,%eax
    aedc:	44 89 e0             	mov    %r12d,%eax
    aedf:	41 0f 44 c7          	cmove  %r15d,%eax
}
    aee3:	48 83 c4 28          	add    $0x28,%rsp
    aee7:	5b                   	pop    %rbx
    aee8:	41 5c                	pop    %r12
    aeea:	41 5d                	pop    %r13
    aeec:	41 5e                	pop    %r14
    aeee:	41 5f                	pop    %r15
    aef0:	5d                   	pop    %rbp
    aef1:	c3                   	retq   
	BT_DBG("hdev %s, bdaddr %s", hdev->name, batostr(bdaddr));
    aef2:	48 89 f7             	mov    %rsi,%rdi
    aef5:	e8 00 00 00 00       	callq  aefa <l2cap_connect_ind+0x13a>
    aefa:	49 8d 56 30          	lea    0x30(%r14),%rdx
    aefe:	48 89 c1             	mov    %rax,%rcx
    af01:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    af08:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    af0f:	31 c0                	xor    %eax,%eax
    af11:	e8 00 00 00 00       	callq  af16 <l2cap_connect_ind+0x156>
    af16:	e9 cb fe ff ff       	jmpq   ade6 <l2cap_connect_ind+0x26>
    af1b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

000000000000af20 <l2cap_connect_cfm>:
{
    af20:	55                   	push   %rbp
    af21:	48 89 e5             	mov    %rsp,%rbp
    af24:	41 57                	push   %r15
    af26:	41 56                	push   %r14
    af28:	41 55                	push   %r13
    af2a:	41 54                	push   %r12
    af2c:	53                   	push   %rbx
    af2d:	48 83 ec 18          	sub    $0x18,%rsp
    af31:	e8 00 00 00 00       	callq  af36 <l2cap_connect_cfm+0x16>
	BT_DBG("hcon %p bdaddr %s status %d", hcon, batostr(&hcon->dst), status);
    af36:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # af3d <l2cap_connect_cfm+0x1d>
{
    af3d:	49 89 fc             	mov    %rdi,%r12
    af40:	89 f3                	mov    %esi,%ebx
	BT_DBG("hcon %p bdaddr %s status %d", hcon, batostr(&hcon->dst), status);
    af42:	0f 85 59 03 00 00    	jne    b2a1 <l2cap_connect_cfm+0x381>
	if (!status) {
    af48:	84 db                	test   %bl,%bl
    af4a:	0f 85 60 01 00 00    	jne    b0b0 <l2cap_connect_cfm+0x190>
	struct l2cap_conn *conn = hcon->l2cap_data;
    af50:	4d 8b b4 24 20 04 00 	mov    0x420(%r12),%r14
    af57:	00 
	if (conn || status)
    af58:	4d 85 f6             	test   %r14,%r14
    af5b:	0f 84 ef 01 00 00    	je     b150 <l2cap_connect_cfm+0x230>
	BT_DBG("conn %p", conn);
    af61:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # af68 <l2cap_connect_cfm+0x48>
    af68:	0f 85 9c 03 00 00    	jne    b30a <l2cap_connect_cfm+0x3ea>
	if (!conn->hcon->out && conn->hcon->type == LE_LINK)
    af6e:	49 8b 06             	mov    (%r14),%rax
    af71:	4d 8d be 40 01 00 00 	lea    0x140(%r14),%r15
    af78:	80 78 22 00          	cmpb   $0x0,0x22(%rax)
    af7c:	0f 85 be 01 00 00    	jne    b140 <l2cap_connect_cfm+0x220>
    af82:	80 78 21 80          	cmpb   $0x80,0x21(%rax)
    af86:	0f 84 38 01 00 00    	je     b0c4 <l2cap_connect_cfm+0x1a4>
    af8c:	49 8d 86 40 01 00 00 	lea    0x140(%r14),%rax
    af93:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
	mutex_lock(&conn->chan_lock);
    af97:	48 8b 7d c8          	mov    -0x38(%rbp),%rdi
	list_for_each_entry(chan, &conn->chan_l, list) {
    af9b:	4d 8d be 30 01 00 00 	lea    0x130(%r14),%r15
	mutex_lock(&conn->chan_lock);
    afa2:	e8 00 00 00 00       	callq  afa7 <l2cap_connect_cfm+0x87>
	list_for_each_entry(chan, &conn->chan_l, list) {
    afa7:	49 8b 86 30 01 00 00 	mov    0x130(%r14),%rax
    afae:	49 39 c7             	cmp    %rax,%r15
    afb1:	48 8d 98 e8 fc ff ff 	lea    -0x318(%rax),%rbx
    afb8:	75 74                	jne    b02e <l2cap_connect_cfm+0x10e>
    afba:	e9 c1 00 00 00       	jmpq   b080 <l2cap_connect_cfm+0x160>
    afbf:	90                   	nop
	ret = del_timer_sync(&work->timer);
    afc0:	48 8d bb 10 01 00 00 	lea    0x110(%rbx),%rdi
			struct sock *sk = chan->sk;
    afc7:	4c 8b 2b             	mov    (%rbx),%r13
    afca:	e8 00 00 00 00       	callq  afcf <l2cap_connect_cfm+0xaf>
	if (ret)
    afcf:	85 c0                	test   %eax,%eax
    afd1:	74 17                	je     afea <l2cap_connect_cfm+0xca>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    afd3:	f0 80 a3 f0 00 00 00 	lock andb $0xfe,0xf0(%rbx)
    afda:	fe 
	asm volatile(LOCK_PREFIX "decl %0; sete %1"
    afdb:	f0 ff 4b 14          	lock decl 0x14(%rbx)
    afdf:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    afe2:	84 c0                	test   %al,%al
    afe4:	0f 85 b6 00 00 00    	jne    b0a0 <l2cap_connect_cfm+0x180>
	lock_sock_nested(sk, 0);
    afea:	31 f6                	xor    %esi,%esi
    afec:	4c 89 ef             	mov    %r13,%rdi
    afef:	e8 00 00 00 00       	callq  aff4 <l2cap_connect_cfm+0xd4>
			__l2cap_state_change(chan, BT_CONNECTED);
    aff4:	be 01 00 00 00       	mov    $0x1,%esi
    aff9:	48 89 df             	mov    %rbx,%rdi
    affc:	e8 8f 50 ff ff       	callq  90 <__l2cap_state_change>
			sk->sk_state_change(sk);
    b001:	4c 89 ef             	mov    %r13,%rdi
    b004:	41 ff 95 58 02 00 00 	callq  *0x258(%r13)
			release_sock(sk);
    b00b:	4c 89 ef             	mov    %r13,%rdi
    b00e:	e8 00 00 00 00       	callq  b013 <l2cap_connect_cfm+0xf3>
	mutex_unlock(&chan->lock);
    b013:	4c 89 e7             	mov    %r12,%rdi
    b016:	e8 00 00 00 00       	callq  b01b <l2cap_connect_cfm+0xfb>
	list_for_each_entry(chan, &conn->chan_l, list) {
    b01b:	48 8b 83 18 03 00 00 	mov    0x318(%rbx),%rax
    b022:	49 39 c7             	cmp    %rax,%r15
    b025:	48 8d 98 e8 fc ff ff 	lea    -0x318(%rax),%rbx
    b02c:	74 52                	je     b080 <l2cap_connect_cfm+0x160>
	mutex_lock(&chan->lock);
    b02e:	4c 8d a3 48 03 00 00 	lea    0x348(%rbx),%r12
    b035:	4c 89 e7             	mov    %r12,%rdi
    b038:	e8 00 00 00 00       	callq  b03d <l2cap_connect_cfm+0x11d>
		if (conn->hcon->type == LE_LINK) {
    b03d:	49 8b 06             	mov    (%r14),%rax
    b040:	80 78 21 80          	cmpb   $0x80,0x21(%rax)
    b044:	74 1a                	je     b060 <l2cap_connect_cfm+0x140>
		} else if (chan->chan_type != L2CAP_CHAN_CONN_ORIENTED) {
    b046:	80 7b 25 03          	cmpb   $0x3,0x25(%rbx)
    b04a:	0f 85 70 ff ff ff    	jne    afc0 <l2cap_connect_cfm+0xa0>
		} else if (chan->state == BT_CONNECT)
    b050:	80 7b 10 05          	cmpb   $0x5,0x10(%rbx)
    b054:	75 bd                	jne    b013 <l2cap_connect_cfm+0xf3>
			l2cap_do_start(chan);
    b056:	48 89 df             	mov    %rbx,%rdi
    b059:	e8 e2 ca ff ff       	callq  7b40 <l2cap_do_start>
    b05e:	eb b3                	jmp    b013 <l2cap_connect_cfm+0xf3>
			if (smp_conn_security(conn, chan->sec_level))
    b060:	0f b6 73 2a          	movzbl 0x2a(%rbx),%esi
    b064:	4c 89 f7             	mov    %r14,%rdi
    b067:	e8 00 00 00 00       	callq  b06c <l2cap_connect_cfm+0x14c>
    b06c:	85 c0                	test   %eax,%eax
    b06e:	74 a3                	je     b013 <l2cap_connect_cfm+0xf3>
				l2cap_chan_ready(chan);
    b070:	48 89 df             	mov    %rbx,%rdi
    b073:	e8 e8 73 ff ff       	callq  2460 <l2cap_chan_ready>
    b078:	eb 99                	jmp    b013 <l2cap_connect_cfm+0xf3>
    b07a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
	mutex_unlock(&conn->chan_lock);
    b080:	48 8b 7d c8          	mov    -0x38(%rbp),%rdi
    b084:	e8 00 00 00 00       	callq  b089 <l2cap_connect_cfm+0x169>
}
    b089:	48 83 c4 18          	add    $0x18,%rsp
    b08d:	31 c0                	xor    %eax,%eax
    b08f:	5b                   	pop    %rbx
    b090:	41 5c                	pop    %r12
    b092:	41 5d                	pop    %r13
    b094:	41 5e                	pop    %r14
    b096:	41 5f                	pop    %r15
    b098:	5d                   	pop    %rbp
    b099:	c3                   	retq   
    b09a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		kfree(c);
    b0a0:	48 89 df             	mov    %rbx,%rdi
    b0a3:	e8 00 00 00 00       	callq  b0a8 <l2cap_connect_cfm+0x188>
    b0a8:	e9 3d ff ff ff       	jmpq   afea <l2cap_connect_cfm+0xca>
    b0ad:	0f 1f 00             	nopl   (%rax)
		l2cap_conn_del(hcon, bt_to_errno(status));
    b0b0:	0f b6 fb             	movzbl %bl,%edi
    b0b3:	e8 00 00 00 00       	callq  b0b8 <l2cap_connect_cfm+0x198>
    b0b8:	4c 89 e7             	mov    %r12,%rdi
    b0bb:	89 c6                	mov    %eax,%esi
    b0bd:	e8 3e be ff ff       	callq  6f00 <l2cap_conn_del>
    b0c2:	eb c5                	jmp    b089 <l2cap_connect_cfm+0x169>
	BT_DBG("");
    b0c4:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # b0cb <l2cap_connect_cfm+0x1ab>
    b0cb:	0f 85 73 02 00 00    	jne    b344 <l2cap_connect_cfm+0x424>
	pchan = l2cap_global_chan_by_scid(BT_LISTEN, L2CAP_CID_LE_DATA,
    b0d1:	49 8b 4e 10          	mov    0x10(%r14),%rcx
    b0d5:	49 8b 56 18          	mov    0x18(%r14),%rdx
    b0d9:	be 04 00 00 00       	mov    $0x4,%esi
    b0de:	bf 04 00 00 00       	mov    $0x4,%edi
    b0e3:	e8 88 56 ff ff       	callq  770 <l2cap_global_chan_by_scid>
	if (!pchan)
    b0e8:	48 85 c0             	test   %rax,%rax
	pchan = l2cap_global_chan_by_scid(BT_LISTEN, L2CAP_CID_LE_DATA,
    b0eb:	49 89 c4             	mov    %rax,%r12
	if (!pchan)
    b0ee:	0f 84 96 01 00 00    	je     b28a <l2cap_connect_cfm+0x36a>
	parent = pchan->sk;
    b0f4:	48 8b 18             	mov    (%rax),%rbx
    b0f7:	31 f6                	xor    %esi,%esi
    b0f9:	48 89 df             	mov    %rbx,%rdi
    b0fc:	e8 00 00 00 00       	callq  b101 <l2cap_connect_cfm+0x1e1>
	return sk->sk_ack_backlog > sk->sk_max_ack_backlog;
    b101:	0f b7 83 84 01 00 00 	movzwl 0x184(%rbx),%eax
	if (sk_acceptq_is_full(parent)) {
    b108:	66 3b 83 86 01 00 00 	cmp    0x186(%rbx),%ax
    b10f:	76 6d                	jbe    b17e <l2cap_connect_cfm+0x25e>
		BT_DBG("backlog full %d", parent->sk_ack_backlog);
    b111:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # b118 <l2cap_connect_cfm+0x1f8>
    b118:	0f 85 09 02 00 00    	jne    b327 <l2cap_connect_cfm+0x407>
    b11e:	4d 8d be 40 01 00 00 	lea    0x140(%r14),%r15
    b125:	4c 89 7d c8          	mov    %r15,-0x38(%rbp)
	release_sock(parent);
    b129:	48 89 df             	mov    %rbx,%rdi
    b12c:	e8 00 00 00 00       	callq  b131 <l2cap_connect_cfm+0x211>
	if (conn->hcon->out && conn->hcon->type == LE_LINK)
    b131:	49 8b 06             	mov    (%r14),%rax
    b134:	80 78 22 00          	cmpb   $0x0,0x22(%rax)
    b138:	0f 84 59 fe ff ff    	je     af97 <l2cap_connect_cfm+0x77>
    b13e:	66 90                	xchg   %ax,%ax
    b140:	80 78 21 80          	cmpb   $0x80,0x21(%rax)
    b144:	74 2a                	je     b170 <l2cap_connect_cfm+0x250>
    b146:	4c 89 7d c8          	mov    %r15,-0x38(%rbp)
    b14a:	e9 48 fe ff ff       	jmpq   af97 <l2cap_connect_cfm+0x77>
    b14f:	90                   	nop
    b150:	4c 89 e7             	mov    %r12,%rdi
    b153:	e8 e8 5d ff ff       	callq  f40 <l2cap_conn_add.part.29>
		if (conn)
    b158:	48 85 c0             	test   %rax,%rax
    b15b:	49 89 c6             	mov    %rax,%r14
    b15e:	0f 84 25 ff ff ff    	je     b089 <l2cap_connect_cfm+0x169>
    b164:	e9 f8 fd ff ff       	jmpq   af61 <l2cap_connect_cfm+0x41>
    b169:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		smp_conn_security(conn, conn->hcon->pending_sec_level);
    b170:	0f b6 70 3f          	movzbl 0x3f(%rax),%esi
    b174:	4c 89 f7             	mov    %r14,%rdi
    b177:	e8 00 00 00 00       	callq  b17c <l2cap_connect_cfm+0x25c>
    b17c:	eb c8                	jmp    b146 <l2cap_connect_cfm+0x226>
	chan = pchan->ops->new_connection(pchan->data);
    b17e:	49 8b 84 24 40 03 00 	mov    0x340(%r12),%rax
    b185:	00 
    b186:	49 8b bc 24 38 03 00 	mov    0x338(%r12),%rdi
    b18d:	00 
    b18e:	ff 50 08             	callq  *0x8(%rax)
	if (!chan)
    b191:	48 85 c0             	test   %rax,%rax
	chan = pchan->ops->new_connection(pchan->data);
    b194:	49 89 c5             	mov    %rax,%r13
	if (!chan)
    b197:	0f 84 81 ff ff ff    	je     b11e <l2cap_connect_cfm+0x1fe>
	sk = chan->sk;
    b19d:	4c 8b 20             	mov    (%rax),%r12
	hci_conn_hold(conn->hcon);
    b1a0:	4d 8b 3e             	mov    (%r14),%r15
	asm volatile(LOCK_PREFIX "incl %0"
    b1a3:	f0 41 ff 47 10       	lock incl 0x10(%r15)
	ret = del_timer_sync(&work->timer);
    b1a8:	49 8d bf a0 00 00 00 	lea    0xa0(%r15),%rdi
    b1af:	e8 00 00 00 00       	callq  b1b4 <l2cap_connect_cfm+0x294>
	if (ret)
    b1b4:	85 c0                	test   %eax,%eax
    b1b6:	74 09                	je     b1c1 <l2cap_connect_cfm+0x2a1>
    b1b8:	f0 41 80 a7 80 00 00 	lock andb $0xfe,0x80(%r15)
    b1bf:	00 fe 
	memcpy(dst, src, sizeof(bdaddr_t));
    b1c1:	49 8b 46 18          	mov    0x18(%r14),%rax
	mutex_lock(&conn->chan_lock);
    b1c5:	4d 8d be 40 01 00 00 	lea    0x140(%r14),%r15
	bt_accept_enqueue(parent, sk);
    b1cc:	4c 89 e6             	mov    %r12,%rsi
    b1cf:	48 89 df             	mov    %rbx,%rdi
    b1d2:	8b 10                	mov    (%rax),%edx
    b1d4:	41 89 94 24 88 02 00 	mov    %edx,0x288(%r12)
    b1db:	00 
    b1dc:	0f b7 40 04          	movzwl 0x4(%rax),%eax
    b1e0:	66 41 89 84 24 8c 02 	mov    %ax,0x28c(%r12)
    b1e7:	00 00 
    b1e9:	49 8b 46 10          	mov    0x10(%r14),%rax
    b1ed:	8b 10                	mov    (%rax),%edx
    b1ef:	41 89 94 24 8e 02 00 	mov    %edx,0x28e(%r12)
    b1f6:	00 
    b1f7:	0f b7 40 04          	movzwl 0x4(%rax),%eax
    b1fb:	66 41 89 84 24 92 02 	mov    %ax,0x292(%r12)
    b202:	00 00 
    b204:	e8 00 00 00 00       	callq  b209 <l2cap_connect_cfm+0x2e9>
	mutex_lock(&conn->chan_lock);
    b209:	4c 89 ff             	mov    %r15,%rdi
    b20c:	4c 89 7d c8          	mov    %r15,-0x38(%rbp)
    b210:	e8 00 00 00 00       	callq  b215 <l2cap_connect_cfm+0x2f5>
	__l2cap_chan_add(conn, chan);
    b215:	4c 89 ee             	mov    %r13,%rsi
    b218:	4c 89 f7             	mov    %r14,%rdi
    b21b:	e8 c0 50 ff ff       	callq  2e0 <__l2cap_chan_add>
	mutex_unlock(&conn->chan_lock);
    b220:	4c 89 ff             	mov    %r15,%rdi
    b223:	e8 00 00 00 00       	callq  b228 <l2cap_connect_cfm+0x308>
	BT_DBG("chan %p state %s timeout %ld", chan,
    b228:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # b22f <l2cap_connect_cfm+0x30f>
	__set_chan_timer(chan, sk->sk_sndtimeo);
    b22f:	49 8d 85 f0 00 00 00 	lea    0xf0(%r13),%rax
    b236:	4d 8b a4 24 a8 01 00 	mov    0x1a8(%r12),%r12
    b23d:	00 
    b23e:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    b242:	0f 85 86 00 00 00    	jne    b2ce <l2cap_connect_cfm+0x3ae>
	ret = del_timer_sync(&work->timer);
    b248:	49 8d bd 10 01 00 00 	lea    0x110(%r13),%rdi
    b24f:	e8 00 00 00 00       	callq  b254 <l2cap_connect_cfm+0x334>
	if (ret)
    b254:	85 c0                	test   %eax,%eax
    b256:	74 42                	je     b29a <l2cap_connect_cfm+0x37a>
    b258:	f0 41 80 a5 f0 00 00 	lock andb $0xfe,0xf0(%r13)
    b25f:	00 fe 
	schedule_delayed_work(work, timeout);
    b261:	48 8b 7d c0          	mov    -0x40(%rbp),%rdi
    b265:	4c 89 e6             	mov    %r12,%rsi
    b268:	e8 00 00 00 00       	callq  b26d <l2cap_connect_cfm+0x34d>
	__l2cap_state_change(chan, BT_CONNECTED);
    b26d:	4c 89 ef             	mov    %r13,%rdi
    b270:	be 01 00 00 00       	mov    $0x1,%esi
    b275:	e8 16 4e ff ff       	callq  90 <__l2cap_state_change>
	parent->sk_data_ready(parent, 0);
    b27a:	31 f6                	xor    %esi,%esi
    b27c:	48 89 df             	mov    %rbx,%rdi
    b27f:	ff 93 60 02 00 00    	callq  *0x260(%rbx)
    b285:	e9 9f fe ff ff       	jmpq   b129 <l2cap_connect_cfm+0x209>
    b28a:	4d 8d be 40 01 00 00 	lea    0x140(%r14),%r15
    b291:	4c 89 7d c8          	mov    %r15,-0x38(%rbp)
    b295:	e9 97 fe ff ff       	jmpq   b131 <l2cap_connect_cfm+0x211>
    b29a:	f0 41 ff 45 14       	lock incl 0x14(%r13)
    b29f:	eb c0                	jmp    b261 <l2cap_connect_cfm+0x341>
	BT_DBG("hcon %p bdaddr %s status %d", hcon, batostr(&hcon->dst), status);
    b2a1:	48 8d 7f 14          	lea    0x14(%rdi),%rdi
    b2a5:	e8 00 00 00 00       	callq  b2aa <l2cap_connect_cfm+0x38a>
    b2aa:	44 0f b6 c3          	movzbl %bl,%r8d
    b2ae:	48 89 c1             	mov    %rax,%rcx
    b2b1:	4c 89 e2             	mov    %r12,%rdx
    b2b4:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    b2bb:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    b2c2:	31 c0                	xor    %eax,%eax
    b2c4:	e8 00 00 00 00       	callq  b2c9 <l2cap_connect_cfm+0x3a9>
    b2c9:	e9 7a fc ff ff       	jmpq   af48 <l2cap_connect_cfm+0x28>
	switch (state) {
    b2ce:	41 0f b6 45 10       	movzbl 0x10(%r13),%eax
    b2d3:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    b2da:	83 e8 01             	sub    $0x1,%eax
    b2dd:	83 f8 08             	cmp    $0x8,%eax
    b2e0:	77 08                	ja     b2ea <l2cap_connect_cfm+0x3ca>
    b2e2:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    b2e9:	00 
	BT_DBG("chan %p state %s timeout %ld", chan,
    b2ea:	4d 89 e0             	mov    %r12,%r8
    b2ed:	4c 89 ea             	mov    %r13,%rdx
    b2f0:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    b2f7:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    b2fe:	31 c0                	xor    %eax,%eax
    b300:	e8 00 00 00 00       	callq  b305 <l2cap_connect_cfm+0x3e5>
    b305:	e9 3e ff ff ff       	jmpq   b248 <l2cap_connect_cfm+0x328>
	BT_DBG("conn %p", conn);
    b30a:	4c 89 f2             	mov    %r14,%rdx
    b30d:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    b314:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    b31b:	31 c0                	xor    %eax,%eax
    b31d:	e8 00 00 00 00       	callq  b322 <l2cap_connect_cfm+0x402>
    b322:	e9 47 fc ff ff       	jmpq   af6e <l2cap_connect_cfm+0x4e>
		BT_DBG("backlog full %d", parent->sk_ack_backlog);
    b327:	0f b7 d0             	movzwl %ax,%edx
    b32a:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    b331:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    b338:	31 c0                	xor    %eax,%eax
    b33a:	e8 00 00 00 00       	callq  b33f <l2cap_connect_cfm+0x41f>
    b33f:	e9 da fd ff ff       	jmpq   b11e <l2cap_connect_cfm+0x1fe>
	BT_DBG("");
    b344:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    b34b:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    b352:	31 c0                	xor    %eax,%eax
    b354:	e8 00 00 00 00       	callq  b359 <l2cap_connect_cfm+0x439>
    b359:	e9 73 fd ff ff       	jmpq   b0d1 <l2cap_connect_cfm+0x1b1>
    b35e:	66 90                	xchg   %ax,%ax

000000000000b360 <l2cap_disconn_ind>:
{
    b360:	55                   	push   %rbp
    b361:	48 89 e5             	mov    %rsp,%rbp
    b364:	53                   	push   %rbx
    b365:	48 83 ec 08          	sub    $0x8,%rsp
    b369:	e8 00 00 00 00       	callq  b36e <l2cap_disconn_ind+0xe>
	BT_DBG("hcon %p", hcon);
    b36e:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # b375 <l2cap_disconn_ind+0x15>
	struct l2cap_conn *conn = hcon->l2cap_data;
    b375:	48 8b 9f 20 04 00 00 	mov    0x420(%rdi),%rbx
	BT_DBG("hcon %p", hcon);
    b37c:	75 18                	jne    b396 <l2cap_disconn_ind+0x36>
	if (!conn)
    b37e:	48 85 db             	test   %rbx,%rbx
		return HCI_ERROR_REMOTE_USER_TERM;
    b381:	b8 13 00 00 00       	mov    $0x13,%eax
	if (!conn)
    b386:	74 07                	je     b38f <l2cap_disconn_ind+0x2f>
	return conn->disc_reason;
    b388:	0f b6 83 b5 00 00 00 	movzbl 0xb5(%rbx),%eax
}
    b38f:	48 83 c4 08          	add    $0x8,%rsp
    b393:	5b                   	pop    %rbx
    b394:	5d                   	pop    %rbp
    b395:	c3                   	retq   
	BT_DBG("hcon %p", hcon);
    b396:	48 89 fa             	mov    %rdi,%rdx
    b399:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    b3a0:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    b3a7:	31 c0                	xor    %eax,%eax
    b3a9:	e8 00 00 00 00       	callq  b3ae <l2cap_disconn_ind+0x4e>
    b3ae:	eb ce                	jmp    b37e <l2cap_disconn_ind+0x1e>

000000000000b3b0 <l2cap_disconn_cfm>:
{
    b3b0:	55                   	push   %rbp
    b3b1:	48 89 e5             	mov    %rsp,%rbp
    b3b4:	41 54                	push   %r12
    b3b6:	53                   	push   %rbx
    b3b7:	e8 00 00 00 00       	callq  b3bc <l2cap_disconn_cfm+0xc>
	BT_DBG("hcon %p reason %d", hcon, reason);
    b3bc:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # b3c3 <l2cap_disconn_cfm+0x13>
{
    b3c3:	48 89 fb             	mov    %rdi,%rbx
	BT_DBG("hcon %p reason %d", hcon, reason);
    b3c6:	44 0f b6 e6          	movzbl %sil,%r12d
    b3ca:	75 19                	jne    b3e5 <l2cap_disconn_cfm+0x35>
	l2cap_conn_del(hcon, bt_to_errno(reason));
    b3cc:	44 89 e7             	mov    %r12d,%edi
    b3cf:	e8 00 00 00 00       	callq  b3d4 <l2cap_disconn_cfm+0x24>
    b3d4:	48 89 df             	mov    %rbx,%rdi
    b3d7:	89 c6                	mov    %eax,%esi
    b3d9:	e8 22 bb ff ff       	callq  6f00 <l2cap_conn_del>
}
    b3de:	5b                   	pop    %rbx
    b3df:	41 5c                	pop    %r12
    b3e1:	31 c0                	xor    %eax,%eax
    b3e3:	5d                   	pop    %rbp
    b3e4:	c3                   	retq   
	BT_DBG("hcon %p reason %d", hcon, reason);
    b3e5:	48 89 fa             	mov    %rdi,%rdx
    b3e8:	44 89 e1             	mov    %r12d,%ecx
    b3eb:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    b3f2:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    b3f9:	31 c0                	xor    %eax,%eax
    b3fb:	e8 00 00 00 00       	callq  b400 <l2cap_disconn_cfm+0x50>
    b400:	eb ca                	jmp    b3cc <l2cap_disconn_cfm+0x1c>
    b402:	0f 1f 40 00          	nopl   0x0(%rax)
    b406:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    b40d:	00 00 00 

000000000000b410 <l2cap_security_cfm>:
{
    b410:	55                   	push   %rbp
    b411:	48 89 e5             	mov    %rsp,%rbp
    b414:	41 57                	push   %r15
    b416:	41 56                	push   %r14
    b418:	41 55                	push   %r13
    b41a:	41 54                	push   %r12
    b41c:	53                   	push   %rbx
    b41d:	48 83 ec 48          	sub    $0x48,%rsp
    b421:	e8 00 00 00 00       	callq  b426 <l2cap_security_cfm+0x16>
	struct l2cap_conn *conn = hcon->l2cap_data;
    b426:	4c 8b b7 20 04 00 00 	mov    0x420(%rdi),%r14
{
    b42d:	48 89 7d b8          	mov    %rdi,-0x48(%rbp)
    b431:	89 f3                	mov    %esi,%ebx
    b433:	41 89 d5             	mov    %edx,%r13d
    b436:	41 89 f4             	mov    %esi,%r12d
    b439:	88 55 b7             	mov    %dl,-0x49(%rbp)
	if (!conn)
    b43c:	4d 85 f6             	test   %r14,%r14
    b43f:	0f 84 c0 00 00 00    	je     b505 <l2cap_security_cfm+0xf5>
	BT_DBG("conn %p", conn);
    b445:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # b44c <l2cap_security_cfm+0x3c>
    b44c:	0f 85 18 04 00 00    	jne    b86a <l2cap_security_cfm+0x45a>
	if (hcon->type == LE_LINK) {
    b452:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    b456:	80 78 21 80          	cmpb   $0x80,0x21(%rax)
    b45a:	0f 84 68 02 00 00    	je     b6c8 <l2cap_security_cfm+0x2b8>
	mutex_lock(&conn->chan_lock);
    b460:	49 8d 86 40 01 00 00 	lea    0x140(%r14),%rax
	list_for_each_entry(chan, &conn->chan_l, list) {
    b467:	4d 8d be 30 01 00 00 	lea    0x130(%r14),%r15
	mutex_lock(&conn->chan_lock);
    b46e:	48 89 c7             	mov    %rax,%rdi
    b471:	48 89 45 a8          	mov    %rax,-0x58(%rbp)
    b475:	e8 00 00 00 00       	callq  b47a <l2cap_security_cfm+0x6a>
	list_for_each_entry(chan, &conn->chan_l, list) {
    b47a:	49 8b 86 30 01 00 00 	mov    0x130(%r14),%rax
    b481:	49 39 c7             	cmp    %rax,%r15
    b484:	4c 8d a8 e8 fc ff ff 	lea    -0x318(%rax),%r13
    b48b:	74 6f                	je     b4fc <l2cap_security_cfm+0xec>
    b48d:	4c 89 75 a0          	mov    %r14,-0x60(%rbp)
    b491:	4d 89 ee             	mov    %r13,%r14
    b494:	0f 1f 40 00          	nopl   0x0(%rax)
	mutex_lock(&chan->lock);
    b498:	49 8d 9e 48 03 00 00 	lea    0x348(%r14),%rbx
    b49f:	48 89 df             	mov    %rbx,%rdi
    b4a2:	e8 00 00 00 00       	callq  b4a7 <l2cap_security_cfm+0x97>
		BT_DBG("chan->scid %d", chan->scid);
    b4a7:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # b4ae <l2cap_security_cfm+0x9e>
    b4ae:	0f 85 52 03 00 00    	jne    b806 <l2cap_security_cfm+0x3f6>
		if (chan->scid == L2CAP_CID_LE_DATA) {
    b4b4:	66 41 83 7e 1c 04    	cmpw   $0x4,0x1c(%r14)
    b4ba:	74 64                	je     b520 <l2cap_security_cfm+0x110>
		(addr[nr / BITS_PER_LONG])) != 0;
    b4bc:	49 8b 86 80 00 00 00 	mov    0x80(%r14),%rax
		if (test_bit(CONF_CONNECT_PEND, &chan->conf_state)) {
    b4c3:	a8 20                	test   $0x20,%al
    b4c5:	75 1a                	jne    b4e1 <l2cap_security_cfm+0xd1>
		if (!status && (chan->state == BT_CONNECTED ||
    b4c7:	45 84 e4             	test   %r12b,%r12b
    b4ca:	41 0f b6 46 10       	movzbl 0x10(%r14),%eax
    b4cf:	74 77                	je     b548 <l2cap_security_cfm+0x138>
		if (chan->state == BT_CONNECT) {
    b4d1:	3c 05                	cmp    $0x5,%al
    b4d3:	0f 84 e7 00 00 00    	je     b5c0 <l2cap_security_cfm+0x1b0>
		} else if (chan->state == BT_CONNECT2) {
    b4d9:	3c 06                	cmp    $0x6,%al
    b4db:	0f 84 2f 01 00 00    	je     b610 <l2cap_security_cfm+0x200>
	mutex_unlock(&chan->lock);
    b4e1:	48 89 df             	mov    %rbx,%rdi
    b4e4:	e8 00 00 00 00       	callq  b4e9 <l2cap_security_cfm+0xd9>
	list_for_each_entry(chan, &conn->chan_l, list) {
    b4e9:	49 8b 86 18 03 00 00 	mov    0x318(%r14),%rax
    b4f0:	49 39 c7             	cmp    %rax,%r15
    b4f3:	4c 8d b0 e8 fc ff ff 	lea    -0x318(%rax),%r14
    b4fa:	75 9c                	jne    b498 <l2cap_security_cfm+0x88>
	mutex_unlock(&conn->chan_lock);
    b4fc:	48 8b 7d a8          	mov    -0x58(%rbp),%rdi
    b500:	e8 00 00 00 00       	callq  b505 <l2cap_security_cfm+0xf5>
}
    b505:	48 83 c4 48          	add    $0x48,%rsp
    b509:	31 c0                	xor    %eax,%eax
    b50b:	5b                   	pop    %rbx
    b50c:	41 5c                	pop    %r12
    b50e:	41 5d                	pop    %r13
    b510:	41 5e                	pop    %r14
    b512:	41 5f                	pop    %r15
    b514:	5d                   	pop    %rbp
    b515:	c3                   	retq   
    b516:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    b51d:	00 00 00 
			if (!status && encrypt) {
    b520:	45 84 e4             	test   %r12b,%r12b
    b523:	75 bc                	jne    b4e1 <l2cap_security_cfm+0xd1>
    b525:	80 7d b7 00          	cmpb   $0x0,-0x49(%rbp)
    b529:	74 b6                	je     b4e1 <l2cap_security_cfm+0xd1>
				chan->sec_level = hcon->sec_level;
    b52b:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
				l2cap_chan_ready(chan);
    b52f:	4c 89 f7             	mov    %r14,%rdi
				chan->sec_level = hcon->sec_level;
    b532:	0f b6 40 3e          	movzbl 0x3e(%rax),%eax
    b536:	41 88 46 2a          	mov    %al,0x2a(%r14)
				l2cap_chan_ready(chan);
    b53a:	e8 21 6f ff ff       	callq  2460 <l2cap_chan_ready>
    b53f:	eb a0                	jmp    b4e1 <l2cap_security_cfm+0xd1>
    b541:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		if (!status && (chan->state == BT_CONNECTED ||
    b548:	3c 07                	cmp    $0x7,%al
    b54a:	74 1c                	je     b568 <l2cap_security_cfm+0x158>
    b54c:	3c 01                	cmp    $0x1,%al
    b54e:	66 90                	xchg   %ax,%ax
    b550:	74 16                	je     b568 <l2cap_security_cfm+0x158>
		if (chan->state == BT_CONNECT) {
    b552:	3c 05                	cmp    $0x5,%al
    b554:	75 83                	jne    b4d9 <l2cap_security_cfm+0xc9>
				l2cap_send_conn_req(chan);
    b556:	4c 89 f7             	mov    %r14,%rdi
    b559:	e8 b2 60 ff ff       	callq  1610 <l2cap_send_conn_req>
    b55e:	66 90                	xchg   %ax,%ax
    b560:	e9 7c ff ff ff       	jmpq   b4e1 <l2cap_security_cfm+0xd1>
    b565:	0f 1f 00             	nopl   (%rax)
			struct sock *sk = chan->sk;
    b568:	49 8b 06             	mov    (%r14),%rax
		asm volatile(LOCK_PREFIX "andb %1,%0"
    b56b:	f0 80 a0 b0 02 00 00 	lock andb $0xfd,0x2b0(%rax)
    b572:	fd 
			sk->sk_state_change(sk);
    b573:	48 89 c7             	mov    %rax,%rdi
    b576:	ff 90 58 02 00 00    	callq  *0x258(%rax)
	if (chan->chan_type != L2CAP_CHAN_CONN_ORIENTED)
    b57c:	41 80 7e 25 03       	cmpb   $0x3,0x25(%r14)
    b581:	0f 85 5a ff ff ff    	jne    b4e1 <l2cap_security_cfm+0xd1>
	if (encrypt == 0x00) {
    b587:	80 7d b7 00          	cmpb   $0x0,-0x49(%rbp)
    b58b:	0f 85 6f 01 00 00    	jne    b700 <l2cap_security_cfm+0x2f0>
		if (chan->sec_level == BT_SECURITY_MEDIUM) {
    b591:	41 0f b6 46 2a       	movzbl 0x2a(%r14),%eax
			__set_chan_timer(chan, L2CAP_ENC_TIMEOUT);
    b596:	bf 88 13 00 00       	mov    $0x1388,%edi
		if (chan->sec_level == BT_SECURITY_MEDIUM) {
    b59b:	3c 02                	cmp    $0x2,%al
    b59d:	74 26                	je     b5c5 <l2cap_security_cfm+0x1b5>
		} else if (chan->sec_level == BT_SECURITY_HIGH)
    b59f:	3c 03                	cmp    $0x3,%al
    b5a1:	0f 85 3a ff ff ff    	jne    b4e1 <l2cap_security_cfm+0xd1>
			l2cap_chan_close(chan, ECONNREFUSED);
    b5a7:	be 6f 00 00 00       	mov    $0x6f,%esi
    b5ac:	4c 89 f7             	mov    %r14,%rdi
    b5af:	e8 00 00 00 00       	callq  b5b4 <l2cap_security_cfm+0x1a4>
    b5b4:	e9 28 ff ff ff       	jmpq   b4e1 <l2cap_security_cfm+0xd1>
    b5b9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
				__set_chan_timer(chan, L2CAP_DISC_TIMEOUT);
    b5c0:	bf 64 00 00 00       	mov    $0x64,%edi
    b5c5:	e8 00 00 00 00       	callq  b5ca <l2cap_security_cfm+0x1ba>
	BT_DBG("chan %p state %s timeout %ld", chan,
    b5ca:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # b5d1 <l2cap_security_cfm+0x1c1>
    b5d1:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    b5d5:	4d 8d ae f0 00 00 00 	lea    0xf0(%r14),%r13
    b5dc:	0f 85 a5 02 00 00    	jne    b887 <l2cap_security_cfm+0x477>
	ret = del_timer_sync(&work->timer);
    b5e2:	49 8d be 10 01 00 00 	lea    0x110(%r14),%rdi
    b5e9:	e8 00 00 00 00       	callq  b5ee <l2cap_security_cfm+0x1de>
	if (ret)
    b5ee:	85 c0                	test   %eax,%eax
    b5f0:	0f 84 c2 00 00 00    	je     b6b8 <l2cap_security_cfm+0x2a8>
    b5f6:	f0 41 80 65 00 fe    	lock andb $0xfe,0x0(%r13)
	schedule_delayed_work(work, timeout);
    b5fc:	48 8b 75 98          	mov    -0x68(%rbp),%rsi
    b600:	4c 89 ef             	mov    %r13,%rdi
    b603:	e8 00 00 00 00       	callq  b608 <l2cap_security_cfm+0x1f8>
    b608:	e9 d4 fe ff ff       	jmpq   b4e1 <l2cap_security_cfm+0xd1>
    b60d:	0f 1f 00             	nopl   (%rax)
			struct sock *sk = chan->sk;
    b610:	4d 8b 2e             	mov    (%r14),%r13
	lock_sock_nested(sk, 0);
    b613:	31 f6                	xor    %esi,%esi
    b615:	4c 89 ef             	mov    %r13,%rdi
    b618:	e8 00 00 00 00       	callq  b61d <l2cap_security_cfm+0x20d>
			if (!status) {
    b61d:	45 84 e4             	test   %r12b,%r12b
    b620:	0f 85 5a 01 00 00    	jne    b780 <l2cap_security_cfm+0x370>
		(addr[nr / BITS_PER_LONG])) != 0;
    b626:	49 8b 85 b0 02 00 00 	mov    0x2b0(%r13),%rax
				if (test_bit(BT_SK_DEFER_SETUP,
    b62d:	a8 01                	test   $0x1,%al
    b62f:	0f 84 13 01 00 00    	je     b748 <l2cap_security_cfm+0x338>
					struct sock *parent = bt_sk(sk)->parent;
    b635:	49 8b 85 a8 02 00 00 	mov    0x2a8(%r13),%rax
					if (parent)
    b63c:	48 85 c0             	test   %rax,%rax
    b63f:	0f 84 a3 01 00 00    	je     b7e8 <l2cap_security_cfm+0x3d8>
						parent->sk_data_ready(parent, 0);
    b645:	31 f6                	xor    %esi,%esi
    b647:	48 89 c7             	mov    %rax,%rdi
    b64a:	ff 90 60 02 00 00    	callq  *0x260(%rax)
					stat = L2CAP_CS_AUTHOR_PEND;
    b650:	41 b9 02 00 00 00    	mov    $0x2,%r9d
					res = L2CAP_CR_PEND;
    b656:	41 ba 01 00 00 00    	mov    $0x1,%r10d
					stat = L2CAP_CS_AUTHOR_PEND;
    b65c:	66 44 89 4d 90       	mov    %r9w,-0x70(%rbp)
					res = L2CAP_CR_PEND;
    b661:	66 44 89 55 98       	mov    %r10w,-0x68(%rbp)
			release_sock(sk);
    b666:	4c 89 ef             	mov    %r13,%rdi
    b669:	e8 00 00 00 00       	callq  b66e <l2cap_security_cfm+0x25e>
			rsp.scid   = cpu_to_le16(chan->dcid);
    b66e:	41 0f b7 46 1a       	movzwl 0x1a(%r14),%eax
			l2cap_send_cmd(conn, chan->ident, L2CAP_CONN_RSP,
    b673:	41 0f b6 76 2b       	movzbl 0x2b(%r14),%esi
    b678:	4c 8d 45 c8          	lea    -0x38(%rbp),%r8
    b67c:	48 8b 7d a0          	mov    -0x60(%rbp),%rdi
    b680:	b9 08 00 00 00       	mov    $0x8,%ecx
    b685:	ba 03 00 00 00       	mov    $0x3,%edx
			rsp.scid   = cpu_to_le16(chan->dcid);
    b68a:	66 89 45 ca          	mov    %ax,-0x36(%rbp)
			rsp.dcid   = cpu_to_le16(chan->scid);
    b68e:	41 0f b7 46 1c       	movzwl 0x1c(%r14),%eax
    b693:	66 89 45 c8          	mov    %ax,-0x38(%rbp)
			rsp.result = cpu_to_le16(res);
    b697:	0f b7 45 98          	movzwl -0x68(%rbp),%eax
    b69b:	66 89 45 cc          	mov    %ax,-0x34(%rbp)
			rsp.status = cpu_to_le16(stat);
    b69f:	0f b7 45 90          	movzwl -0x70(%rbp),%eax
    b6a3:	66 89 45 ce          	mov    %ax,-0x32(%rbp)
			l2cap_send_cmd(conn, chan->ident, L2CAP_CONN_RSP,
    b6a7:	e8 14 5d ff ff       	callq  13c0 <l2cap_send_cmd>
    b6ac:	e9 30 fe ff ff       	jmpq   b4e1 <l2cap_security_cfm+0xd1>
    b6b1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    b6b8:	f0 41 ff 46 14       	lock incl 0x14(%r14)
    b6bd:	e9 3a ff ff ff       	jmpq   b5fc <l2cap_security_cfm+0x1ec>
    b6c2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
		if (!status && encrypt)
    b6c8:	84 db                	test   %bl,%bl
    b6ca:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    b6d0:	0f 84 92 00 00 00    	je     b768 <l2cap_security_cfm+0x358>
	ret = del_timer_sync(&work->timer);
    b6d6:	49 8d be d8 00 00 00 	lea    0xd8(%r14),%rdi
    b6dd:	e8 00 00 00 00       	callq  b6e2 <l2cap_security_cfm+0x2d2>
	if (ret)
    b6e2:	85 c0                	test   %eax,%eax
    b6e4:	0f 84 76 fd ff ff    	je     b460 <l2cap_security_cfm+0x50>
		asm volatile(LOCK_PREFIX "andb %1,%0"
    b6ea:	f0 41 80 a6 b8 00 00 	lock andb $0xfe,0xb8(%r14)
    b6f1:	00 fe 
    b6f3:	e9 68 fd ff ff       	jmpq   b460 <l2cap_security_cfm+0x50>
    b6f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    b6ff:	00 
		if (chan->sec_level == BT_SECURITY_MEDIUM)
    b700:	41 80 7e 2a 02       	cmpb   $0x2,0x2a(%r14)
    b705:	0f 85 d6 fd ff ff    	jne    b4e1 <l2cap_security_cfm+0xd1>
	ret = del_timer_sync(&work->timer);
    b70b:	49 8d be 10 01 00 00 	lea    0x110(%r14),%rdi
    b712:	e8 00 00 00 00       	callq  b717 <l2cap_security_cfm+0x307>
	if (ret)
    b717:	85 c0                	test   %eax,%eax
    b719:	0f 84 c2 fd ff ff    	je     b4e1 <l2cap_security_cfm+0xd1>
    b71f:	f0 41 80 a6 f0 00 00 	lock andb $0xfe,0xf0(%r14)
    b726:	00 fe 
	asm volatile(LOCK_PREFIX "decl %0; sete %1"
    b728:	f0 41 ff 4e 14       	lock decl 0x14(%r14)
    b72d:	0f 94 c0             	sete   %al
	if (atomic_dec_and_test(&c->refcnt))
    b730:	84 c0                	test   %al,%al
    b732:	0f 84 a9 fd ff ff    	je     b4e1 <l2cap_security_cfm+0xd1>
		kfree(c);
    b738:	4c 89 f7             	mov    %r14,%rdi
    b73b:	e8 00 00 00 00       	callq  b740 <l2cap_security_cfm+0x330>
    b740:	e9 9c fd ff ff       	jmpq   b4e1 <l2cap_security_cfm+0xd1>
    b745:	0f 1f 00             	nopl   (%rax)
					__l2cap_state_change(chan, BT_CONFIG);
    b748:	4c 89 f7             	mov    %r14,%rdi
    b74b:	be 07 00 00 00       	mov    $0x7,%esi
    b750:	e8 3b 49 ff ff       	callq  90 <__l2cap_state_change>
					stat = L2CAP_CS_NO_INFO;
    b755:	31 ff                	xor    %edi,%edi
					res = L2CAP_CR_SUCCESS;
    b757:	45 31 c0             	xor    %r8d,%r8d
					stat = L2CAP_CS_NO_INFO;
    b75a:	66 89 7d 90          	mov    %di,-0x70(%rbp)
					res = L2CAP_CR_SUCCESS;
    b75e:	66 44 89 45 98       	mov    %r8w,-0x68(%rbp)
    b763:	e9 fe fe ff ff       	jmpq   b666 <l2cap_security_cfm+0x256>
		if (!status && encrypt)
    b768:	45 84 ed             	test   %r13b,%r13b
    b76b:	0f 84 65 ff ff ff    	je     b6d6 <l2cap_security_cfm+0x2c6>
			smp_distribute_keys(conn, 0);
    b771:	31 f6                	xor    %esi,%esi
    b773:	4c 89 f7             	mov    %r14,%rdi
    b776:	e8 00 00 00 00       	callq  b77b <l2cap_security_cfm+0x36b>
    b77b:	e9 56 ff ff ff       	jmpq   b6d6 <l2cap_security_cfm+0x2c6>
				__l2cap_state_change(chan, BT_DISCONN);
    b780:	be 08 00 00 00       	mov    $0x8,%esi
    b785:	4c 89 f7             	mov    %r14,%rdi
    b788:	e8 03 49 ff ff       	callq  90 <__l2cap_state_change>
				__set_chan_timer(chan, L2CAP_DISC_TIMEOUT);
    b78d:	bf 64 00 00 00       	mov    $0x64,%edi
    b792:	e8 00 00 00 00       	callq  b797 <l2cap_security_cfm+0x387>
	BT_DBG("chan %p state %s timeout %ld", chan,
    b797:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # b79e <l2cap_security_cfm+0x38e>
    b79e:	48 89 45 98          	mov    %rax,-0x68(%rbp)
    b7a2:	4d 8d 8e f0 00 00 00 	lea    0xf0(%r14),%r9
    b7a9:	75 7a                	jne    b825 <l2cap_security_cfm+0x415>
	ret = del_timer_sync(&work->timer);
    b7ab:	49 8d be 10 01 00 00 	lea    0x110(%r14),%rdi
    b7b2:	4c 89 4d 90          	mov    %r9,-0x70(%rbp)
    b7b6:	e8 00 00 00 00       	callq  b7bb <l2cap_security_cfm+0x3ab>
	if (ret)
    b7bb:	85 c0                	test   %eax,%eax
    b7bd:	4c 8b 4d 90          	mov    -0x70(%rbp),%r9
    b7c1:	74 3c                	je     b7ff <l2cap_security_cfm+0x3ef>
    b7c3:	f0 41 80 21 fe       	lock andb $0xfe,(%r9)
	schedule_delayed_work(work, timeout);
    b7c8:	48 8b 75 98          	mov    -0x68(%rbp),%rsi
    b7cc:	4c 89 cf             	mov    %r9,%rdi
    b7cf:	e8 00 00 00 00       	callq  b7d4 <l2cap_security_cfm+0x3c4>
				stat = L2CAP_CS_NO_INFO;
    b7d4:	31 c9                	xor    %ecx,%ecx
				res = L2CAP_CR_SEC_BLOCK;
    b7d6:	be 03 00 00 00       	mov    $0x3,%esi
				stat = L2CAP_CS_NO_INFO;
    b7db:	66 89 4d 90          	mov    %cx,-0x70(%rbp)
				res = L2CAP_CR_SEC_BLOCK;
    b7df:	66 89 75 98          	mov    %si,-0x68(%rbp)
    b7e3:	e9 7e fe ff ff       	jmpq   b666 <l2cap_security_cfm+0x256>
					stat = L2CAP_CS_AUTHOR_PEND;
    b7e8:	b8 02 00 00 00       	mov    $0x2,%eax
					res = L2CAP_CR_PEND;
    b7ed:	ba 01 00 00 00       	mov    $0x1,%edx
					stat = L2CAP_CS_AUTHOR_PEND;
    b7f2:	66 89 45 90          	mov    %ax,-0x70(%rbp)
					res = L2CAP_CR_PEND;
    b7f6:	66 89 55 98          	mov    %dx,-0x68(%rbp)
    b7fa:	e9 67 fe ff ff       	jmpq   b666 <l2cap_security_cfm+0x256>
	asm volatile(LOCK_PREFIX "incl %0"
    b7ff:	f0 41 ff 46 14       	lock incl 0x14(%r14)
    b804:	eb c2                	jmp    b7c8 <l2cap_security_cfm+0x3b8>
		BT_DBG("chan->scid %d", chan->scid);
    b806:	41 0f b7 56 1c       	movzwl 0x1c(%r14),%edx
    b80b:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    b812:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    b819:	31 c0                	xor    %eax,%eax
    b81b:	e8 00 00 00 00       	callq  b820 <l2cap_security_cfm+0x410>
    b820:	e9 8f fc ff ff       	jmpq   b4b4 <l2cap_security_cfm+0xa4>
    b825:	41 0f b6 46 10       	movzbl 0x10(%r14),%eax
    b82a:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    b831:	83 e8 01             	sub    $0x1,%eax
    b834:	83 f8 08             	cmp    $0x8,%eax
    b837:	77 08                	ja     b841 <l2cap_security_cfm+0x431>
    b839:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    b840:	00 
	BT_DBG("chan %p state %s timeout %ld", chan,
    b841:	4c 8b 45 98          	mov    -0x68(%rbp),%r8
    b845:	4c 89 f2             	mov    %r14,%rdx
    b848:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    b84f:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    b856:	31 c0                	xor    %eax,%eax
    b858:	4c 89 4d 90          	mov    %r9,-0x70(%rbp)
    b85c:	e8 00 00 00 00       	callq  b861 <l2cap_security_cfm+0x451>
    b861:	4c 8b 4d 90          	mov    -0x70(%rbp),%r9
    b865:	e9 41 ff ff ff       	jmpq   b7ab <l2cap_security_cfm+0x39b>
	BT_DBG("conn %p", conn);
    b86a:	4c 89 f2             	mov    %r14,%rdx
    b86d:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    b874:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    b87b:	31 c0                	xor    %eax,%eax
    b87d:	e8 00 00 00 00       	callq  b882 <l2cap_security_cfm+0x472>
    b882:	e9 cb fb ff ff       	jmpq   b452 <l2cap_security_cfm+0x42>
    b887:	41 0f b6 46 10       	movzbl 0x10(%r14),%eax
    b88c:	48 c7 c1 00 00 00 00 	mov    $0x0,%rcx
    b893:	83 e8 01             	sub    $0x1,%eax
    b896:	83 f8 08             	cmp    $0x8,%eax
    b899:	77 08                	ja     b8a3 <l2cap_security_cfm+0x493>
    b89b:	48 8b 0c c5 00 00 00 	mov    0x0(,%rax,8),%rcx
    b8a2:	00 
    b8a3:	4c 8b 45 98          	mov    -0x68(%rbp),%r8
    b8a7:	4c 89 f2             	mov    %r14,%rdx
    b8aa:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    b8b1:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    b8b8:	31 c0                	xor    %eax,%eax
    b8ba:	e8 00 00 00 00       	callq  b8bf <l2cap_security_cfm+0x4af>
    b8bf:	e9 1e fd ff ff       	jmpq   b5e2 <l2cap_security_cfm+0x1d2>
    b8c4:	66 90                	xchg   %ax,%ax
    b8c6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    b8cd:	00 00 00 

000000000000b8d0 <l2cap_recv_acldata>:
{
    b8d0:	55                   	push   %rbp
    b8d1:	48 89 e5             	mov    %rsp,%rbp
    b8d4:	41 56                	push   %r14
    b8d6:	41 55                	push   %r13
    b8d8:	41 54                	push   %r12
    b8da:	53                   	push   %rbx
    b8db:	e8 00 00 00 00       	callq  b8e0 <l2cap_recv_acldata+0x10>
	struct l2cap_conn *conn = hcon->l2cap_data;
    b8e0:	48 8b 9f 20 04 00 00 	mov    0x420(%rdi),%rbx
{
    b8e7:	49 89 f4             	mov    %rsi,%r12
    b8ea:	41 89 d5             	mov    %edx,%r13d
	if (!conn)
    b8ed:	48 85 db             	test   %rbx,%rbx
    b8f0:	0f 84 7a 02 00 00    	je     bb70 <l2cap_recv_acldata+0x2a0>
	BT_DBG("conn %p len %d flags 0x%x", conn, skb->len, flags);
    b8f6:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # b8fd <l2cap_recv_acldata+0x2d>
    b8fd:	0f 85 83 02 00 00    	jne    bb86 <l2cap_recv_acldata+0x2b6>
	if (!(flags & ACL_CONT)) {
    b903:	41 83 e5 01          	and    $0x1,%r13d
    b907:	0f 85 bb 00 00 00    	jne    b9c8 <l2cap_recv_acldata+0xf8>
		if (conn->rx_len) {
    b90d:	8b 83 b0 00 00 00    	mov    0xb0(%rbx),%eax
    b913:	85 c0                	test   %eax,%eax
    b915:	0f 85 d5 01 00 00    	jne    baf0 <l2cap_recv_acldata+0x220>
		if (skb->len < L2CAP_HDR_SIZE) {
    b91b:	41 8b 74 24 68       	mov    0x68(%r12),%esi
    b920:	83 fe 03             	cmp    $0x3,%esi
    b923:	0f 86 a7 01 00 00    	jbe    bad0 <l2cap_recv_acldata+0x200>
		len = __le16_to_cpu(hdr->len) + L2CAP_HDR_SIZE;
    b929:	49 8b 84 24 e0 00 00 	mov    0xe0(%r12),%rax
    b930:	00 
    b931:	44 0f b7 28          	movzwl (%rax),%r13d
    b935:	41 83 c5 04          	add    $0x4,%r13d
		if (len == skb->len) {
    b939:	44 39 ee             	cmp    %r13d,%esi
    b93c:	0f 84 1e 02 00 00    	je     bb60 <l2cap_recv_acldata+0x290>
		BT_DBG("Start: total len %d, frag len %d", len, skb->len);
    b942:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # b949 <l2cap_recv_acldata+0x79>
    b949:	0f 85 82 02 00 00    	jne    bbd1 <l2cap_recv_acldata+0x301>
		if (skb->len > len) {
    b94f:	44 39 ee             	cmp    %r13d,%esi
    b952:	0f 87 30 01 00 00    	ja     ba88 <l2cap_recv_acldata+0x1b8>
	if ((skb = alloc_skb(len + BT_SKB_RESERVE, how))) {
    b958:	41 8d 7d 08          	lea    0x8(%r13),%edi
	return __alloc_skb(size, priority, 0, NUMA_NO_NODE);
    b95c:	31 d2                	xor    %edx,%edx
    b95e:	b9 ff ff ff ff       	mov    $0xffffffff,%ecx
    b963:	be 20 00 00 00       	mov    $0x20,%esi
    b968:	e8 00 00 00 00       	callq  b96d <l2cap_recv_acldata+0x9d>
    b96d:	48 85 c0             	test   %rax,%rax
    b970:	0f 84 d1 01 00 00    	je     bb47 <l2cap_recv_acldata+0x277>
	skb->data += len;
    b976:	48 83 80 e0 00 00 00 	addq   $0x8,0xe0(%rax)
    b97d:	08 
	skb->tail += len;
    b97e:	83 80 cc 00 00 00 08 	addl   $0x8,0xcc(%rax)
		skb_copy_from_linear_data(skb, skb_put(conn->rx_skb, skb->len),
    b985:	48 89 c7             	mov    %rax,%rdi
		bt_cb(skb)->incoming  = 0;
    b988:	c6 40 29 00          	movb   $0x0,0x29(%rax)
		conn->rx_skb = bt_skb_alloc(len, GFP_ATOMIC);
    b98c:	48 89 83 a8 00 00 00 	mov    %rax,0xa8(%rbx)
		skb_copy_from_linear_data(skb, skb_put(conn->rx_skb, skb->len),
    b993:	45 8b 74 24 68       	mov    0x68(%r12),%r14d
    b998:	44 89 f6             	mov    %r14d,%esi
    b99b:	e8 00 00 00 00       	callq  b9a0 <l2cap_recv_acldata+0xd0>

static inline void skb_copy_from_linear_data(const struct sk_buff *skb,
					     void *to,
					     const unsigned int len)
{
	memcpy(to, skb->data, len);
    b9a0:	49 8b b4 24 e0 00 00 	mov    0xe0(%r12),%rsi
    b9a7:	00 
    b9a8:	4c 89 f2             	mov    %r14,%rdx
    b9ab:	48 89 c7             	mov    %rax,%rdi
    b9ae:	e8 00 00 00 00       	callq  b9b3 <l2cap_recv_acldata+0xe3>
		conn->rx_len = len - skb->len;
    b9b3:	45 2b 6c 24 68       	sub    0x68(%r12),%r13d
    b9b8:	44 89 ab b0 00 00 00 	mov    %r13d,0xb0(%rbx)
    b9bf:	eb 6f                	jmp    ba30 <l2cap_recv_acldata+0x160>
    b9c1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
		BT_DBG("Cont: frag len %d (expecting %d)", skb->len, conn->rx_len);
    b9c8:	f6 05 00 00 00 00 04 	testb  $0x4,0x0(%rip)        # b9cf <l2cap_recv_acldata+0xff>
    b9cf:	0f 85 d7 01 00 00    	jne    bbac <l2cap_recv_acldata+0x2dc>
		if (!conn->rx_len) {
    b9d5:	8b 93 b0 00 00 00    	mov    0xb0(%rbx),%edx
    b9db:	85 d2                	test   %edx,%edx
    b9dd:	0f 84 c5 00 00 00    	je     baa8 <l2cap_recv_acldata+0x1d8>
		if (skb->len > conn->rx_len) {
    b9e3:	45 8b 6c 24 68       	mov    0x68(%r12),%r13d
    b9e8:	44 39 ea             	cmp    %r13d,%edx
    b9eb:	72 5b                	jb     ba48 <l2cap_recv_acldata+0x178>
		skb_copy_from_linear_data(skb, skb_put(conn->rx_skb, skb->len),
    b9ed:	48 8b bb a8 00 00 00 	mov    0xa8(%rbx),%rdi
    b9f4:	44 89 ee             	mov    %r13d,%esi
    b9f7:	e8 00 00 00 00       	callq  b9fc <l2cap_recv_acldata+0x12c>
    b9fc:	49 8b b4 24 e0 00 00 	mov    0xe0(%r12),%rsi
    ba03:	00 
    ba04:	44 89 ea             	mov    %r13d,%edx
    ba07:	48 89 c7             	mov    %rax,%rdi
    ba0a:	e8 00 00 00 00       	callq  ba0f <l2cap_recv_acldata+0x13f>
		conn->rx_len -= skb->len;
    ba0f:	8b 83 b0 00 00 00    	mov    0xb0(%rbx),%eax
    ba15:	41 2b 44 24 68       	sub    0x68(%r12),%eax
		if (!conn->rx_len) {
    ba1a:	85 c0                	test   %eax,%eax
		conn->rx_len -= skb->len;
    ba1c:	89 83 b0 00 00 00    	mov    %eax,0xb0(%rbx)
		if (!conn->rx_len) {
    ba22:	0f 84 10 01 00 00    	je     bb38 <l2cap_recv_acldata+0x268>
    ba28:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    ba2f:	00 
	kfree_skb(skb);
    ba30:	4c 89 e7             	mov    %r12,%rdi
    ba33:	e8 00 00 00 00       	callq  ba38 <l2cap_recv_acldata+0x168>
}
    ba38:	5b                   	pop    %rbx
    ba39:	41 5c                	pop    %r12
    ba3b:	41 5d                	pop    %r13
    ba3d:	41 5e                	pop    %r14
    ba3f:	31 c0                	xor    %eax,%eax
    ba41:	5d                   	pop    %rbp
    ba42:	c3                   	retq   
    ba43:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
			BT_ERR("Fragment is too long (len %d, expected %d)",
    ba48:	44 89 ee             	mov    %r13d,%esi
    ba4b:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    ba52:	31 c0                	xor    %eax,%eax
    ba54:	e8 00 00 00 00       	callq  ba59 <l2cap_recv_acldata+0x189>
			kfree_skb(conn->rx_skb);
    ba59:	48 8b bb a8 00 00 00 	mov    0xa8(%rbx),%rdi
    ba60:	e8 00 00 00 00       	callq  ba65 <l2cap_recv_acldata+0x195>
			conn->rx_skb = NULL;
    ba65:	48 c7 83 a8 00 00 00 	movq   $0x0,0xa8(%rbx)
    ba6c:	00 00 00 00 
			conn->rx_len = 0;
    ba70:	c7 83 b0 00 00 00 00 	movl   $0x0,0xb0(%rbx)
    ba77:	00 00 00 
			l2cap_conn_unreliable(conn, ECOMM);
    ba7a:	48 89 df             	mov    %rbx,%rdi
    ba7d:	e8 1e 54 ff ff       	callq  ea0 <l2cap_conn_unreliable.constprop.37>
			goto drop;
    ba82:	eb ac                	jmp    ba30 <l2cap_recv_acldata+0x160>
    ba84:	0f 1f 40 00          	nopl   0x0(%rax)
			BT_ERR("Frame is too long (len %d, expected len %d)",
    ba88:	44 89 ea             	mov    %r13d,%edx
    ba8b:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    ba92:	31 c0                	xor    %eax,%eax
    ba94:	e8 00 00 00 00       	callq  ba99 <l2cap_recv_acldata+0x1c9>
			l2cap_conn_unreliable(conn, ECOMM);
    ba99:	48 89 df             	mov    %rbx,%rdi
    ba9c:	e8 ff 53 ff ff       	callq  ea0 <l2cap_conn_unreliable.constprop.37>
			goto drop;
    baa1:	eb 8d                	jmp    ba30 <l2cap_recv_acldata+0x160>
    baa3:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
			BT_ERR("Unexpected continuation frame (len %d)", skb->len);
    baa8:	41 8b 74 24 68       	mov    0x68(%r12),%esi
    baad:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    bab4:	31 c0                	xor    %eax,%eax
    bab6:	e8 00 00 00 00       	callq  babb <l2cap_recv_acldata+0x1eb>
			l2cap_conn_unreliable(conn, ECOMM);
    babb:	48 89 df             	mov    %rbx,%rdi
    babe:	e8 dd 53 ff ff       	callq  ea0 <l2cap_conn_unreliable.constprop.37>
			goto drop;
    bac3:	e9 68 ff ff ff       	jmpq   ba30 <l2cap_recv_acldata+0x160>
    bac8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
    bacf:	00 
			BT_ERR("Frame is too short (len %d)", skb->len);
    bad0:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    bad7:	31 c0                	xor    %eax,%eax
    bad9:	e8 00 00 00 00       	callq  bade <l2cap_recv_acldata+0x20e>
			l2cap_conn_unreliable(conn, ECOMM);
    bade:	48 89 df             	mov    %rbx,%rdi
    bae1:	e8 ba 53 ff ff       	callq  ea0 <l2cap_conn_unreliable.constprop.37>
			goto drop;
    bae6:	e9 45 ff ff ff       	jmpq   ba30 <l2cap_recv_acldata+0x160>
    baeb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
			BT_ERR("Unexpected start frame (len %d)", skb->len);
    baf0:	41 8b 74 24 68       	mov    0x68(%r12),%esi
    baf5:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    bafc:	31 c0                	xor    %eax,%eax
    bafe:	e8 00 00 00 00       	callq  bb03 <l2cap_recv_acldata+0x233>
			kfree_skb(conn->rx_skb);
    bb03:	48 8b bb a8 00 00 00 	mov    0xa8(%rbx),%rdi
    bb0a:	e8 00 00 00 00       	callq  bb0f <l2cap_recv_acldata+0x23f>
			conn->rx_skb = NULL;
    bb0f:	48 c7 83 a8 00 00 00 	movq   $0x0,0xa8(%rbx)
    bb16:	00 00 00 00 
			conn->rx_len = 0;
    bb1a:	c7 83 b0 00 00 00 00 	movl   $0x0,0xb0(%rbx)
    bb21:	00 00 00 
			l2cap_conn_unreliable(conn, ECOMM);
    bb24:	48 89 df             	mov    %rbx,%rdi
    bb27:	e8 74 53 ff ff       	callq  ea0 <l2cap_conn_unreliable.constprop.37>
    bb2c:	e9 ea fd ff ff       	jmpq   b91b <l2cap_recv_acldata+0x4b>
    bb31:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
			l2cap_recv_frame(conn, conn->rx_skb);
    bb38:	48 8b b3 a8 00 00 00 	mov    0xa8(%rbx),%rsi
    bb3f:	48 89 df             	mov    %rbx,%rdi
    bb42:	e8 99 d5 ff ff       	callq  90e0 <l2cap_recv_frame>
			conn->rx_skb = NULL;
    bb47:	48 c7 83 a8 00 00 00 	movq   $0x0,0xa8(%rbx)
    bb4e:	00 00 00 00 
    bb52:	e9 d9 fe ff ff       	jmpq   ba30 <l2cap_recv_acldata+0x160>
    bb57:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
    bb5e:	00 00 
			l2cap_recv_frame(conn, skb);
    bb60:	4c 89 e6             	mov    %r12,%rsi
    bb63:	48 89 df             	mov    %rbx,%rdi
    bb66:	e8 75 d5 ff ff       	callq  90e0 <l2cap_recv_frame>
			return 0;
    bb6b:	e9 c8 fe ff ff       	jmpq   ba38 <l2cap_recv_acldata+0x168>
    bb70:	e8 cb 53 ff ff       	callq  f40 <l2cap_conn_add.part.29>
	if (!conn)
    bb75:	48 85 c0             	test   %rax,%rax
    bb78:	48 89 c3             	mov    %rax,%rbx
    bb7b:	0f 85 75 fd ff ff    	jne    b8f6 <l2cap_recv_acldata+0x26>
    bb81:	e9 aa fe ff ff       	jmpq   ba30 <l2cap_recv_acldata+0x160>
	BT_DBG("conn %p len %d flags 0x%x", conn, skb->len, flags);
    bb86:	41 8b 4c 24 68       	mov    0x68(%r12),%ecx
    bb8b:	45 0f b7 c5          	movzwl %r13w,%r8d
    bb8f:	48 89 da             	mov    %rbx,%rdx
    bb92:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    bb99:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    bba0:	31 c0                	xor    %eax,%eax
    bba2:	e8 00 00 00 00       	callq  bba7 <l2cap_recv_acldata+0x2d7>
    bba7:	e9 57 fd ff ff       	jmpq   b903 <l2cap_recv_acldata+0x33>
		BT_DBG("Cont: frag len %d (expecting %d)", skb->len, conn->rx_len);
    bbac:	8b 8b b0 00 00 00    	mov    0xb0(%rbx),%ecx
    bbb2:	41 8b 54 24 68       	mov    0x68(%r12),%edx
    bbb7:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    bbbe:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    bbc5:	31 c0                	xor    %eax,%eax
    bbc7:	e8 00 00 00 00       	callq  bbcc <l2cap_recv_acldata+0x2fc>
    bbcc:	e9 04 fe ff ff       	jmpq   b9d5 <l2cap_recv_acldata+0x105>
		BT_DBG("Start: total len %d, frag len %d", len, skb->len);
    bbd1:	89 f1                	mov    %esi,%ecx
    bbd3:	44 89 ea             	mov    %r13d,%edx
    bbd6:	48 c7 c6 00 00 00 00 	mov    $0x0,%rsi
    bbdd:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
    bbe4:	31 c0                	xor    %eax,%eax
    bbe6:	e8 00 00 00 00       	callq  bbeb <l2cap_recv_acldata+0x31b>
    bbeb:	41 8b 74 24 68       	mov    0x68(%r12),%esi
    bbf0:	e9 5a fd ff ff       	jmpq   b94f <l2cap_recv_acldata+0x7f>
    bbf5:	90                   	nop
    bbf6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
    bbfd:	00 00 00 

000000000000bc00 <l2cap_exit>:

	return 0;
}

void l2cap_exit(void)
{
    bc00:	55                   	push   %rbp
    bc01:	48 89 e5             	mov    %rsp,%rbp
    bc04:	e8 00 00 00 00       	callq  bc09 <l2cap_exit+0x9>
	debugfs_remove(l2cap_debugfs);
    bc09:	48 8b 3d 00 00 00 00 	mov    0x0(%rip),%rdi        # bc10 <l2cap_exit+0x10>
    bc10:	e8 00 00 00 00       	callq  bc15 <l2cap_exit+0x15>
	l2cap_cleanup_sockets();
    bc15:	e8 00 00 00 00       	callq  bc1a <l2cap_exit+0x1a>
}
    bc1a:	5d                   	pop    %rbp
    bc1b:	c3                   	retq   

Disassembly of section .init.text:

0000000000000000 <l2cap_init>:
{
   0:	55                   	push   %rbp
   1:	48 89 e5             	mov    %rsp,%rbp
   4:	e8 00 00 00 00       	callq  9 <l2cap_init+0x9>
   9:	85 c0                	test   %eax,%eax
   b:	78 40                	js     4d <l2cap_init+0x4d>
   d:	48 8b 15 00 00 00 00 	mov    0x0(%rip),%rdx        # 14 <l2cap_init+0x14>
	list_for_each_entry(c, &chan_list, global_l) {
  14:	48 85 d2             	test   %rdx,%rdx
  17:	74 32                	je     4b <l2cap_init+0x4b>
{
  19:	31 c9                	xor    %ecx,%ecx
  1b:	49 c7 c0 00 00 00 00 	mov    $0x0,%r8
	list_for_each_entry(c, &chan_list, global_l) {
  22:	be 24 01 00 00       	mov    $0x124,%esi
  27:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
  2e:	e8 00 00 00 00       	callq  33 <l2cap_init+0x33>
  33:	48 85 c0             	test   %rax,%rax
  36:	48 89 05 00 00 00 00 	mov    %rax,0x0(%rip)        # 3d <l2cap_init+0x3d>
  3d:	75 0c                	jne    4b <l2cap_init+0x4b>
  3f:	48 c7 c7 00 00 00 00 	mov    $0x0,%rdi
		if (c->sport == psm && !bacmp(&bt_sk(c->sk)->src, src))
  46:	e8 00 00 00 00       	callq  4b <l2cap_init+0x4b>
  4b:	31 c0                	xor    %eax,%eax
	return memcmp(ba1, ba2, sizeof(bdaddr_t));
  4d:	5d                   	pop    %rbp
  4e:	c3                   	retq   
