import cpp

/* Get kmalloc slab size rounding up provided size. */
bindingset[size]
string kmallocSlab(int size) {
	size > 4096    and size <= 8192 and result = "kmalloc-8192"
	or size > 2048 and size <= 4096 and result = "kmalloc-4096"
	or size > 1024 and size <= 2048 and result = "kmalloc-2048"
	or size > 512  and size <= 1024 and result = "kmalloc-1024"
	or size > 256  and size <= 512  and result = "kmalloc-512"
	or size > 192  and size <= 256  and result = "kmalloc-256"
	or size > 128  and size <= 192  and result = "kmalloc-192"
	or size > 96   and size <= 128  and result = "kmalloc-128"
	or size > 64   and size <= 96   and result = "kmalloc-96"
	or size > 32   and size <= 64   and result = "kmalloc-64"
	or size > 16   and size <= 32   and result = "kmalloc-32"
	or size > 8    and size <= 16   and result = "kmalloc-16"
	or size > 0    and size <= 8    and result = "kmalloc-8"
}

class KernelFunc extends Function {
	/* Whether this function is declared with __attribute__((section(sec))) */
	bindingset[sec]
	predicate isInSection(string sec) {
		exists(Attribute a |
			a = this.getAnAttribute()
			and a.hasName("section")
			and a.getArgument(0).getValueText() = sec
		)
	}

	/* Whether this function is declared with __attribute__((always_inline)) */
	predicate isAlwaysInline() {
		exists(Attribute a |
			a = this.getAnAttribute()
			and a.hasName("always_inline")
		)
	}
}
