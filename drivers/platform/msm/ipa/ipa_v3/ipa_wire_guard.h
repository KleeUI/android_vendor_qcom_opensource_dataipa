/* SPDX-License-Identifier: GPL-2.0-only */
/* Isolated IPA install-request guard. Uses the production QMI descriptors. */
#ifndef IPA_INSTALL_WIRE_GUARD_H
#define IPA_INSTALL_WIRE_GUARD_H

static unsigned int ipa_wire_u16(const unsigned char *p)
{
	return p[0] | ((unsigned int)p[1] << 8);
}

static bool ipa_wire_known(unsigned int type, const struct qmi_elem_info *ei)
{
	for (; ei->data_type != QMI_EOTI; ei++)
		if (ei->tlv_type == type)
			return true;
	return false;
}

static int ipa_qmi_wire_validate(const void *data, size_t len,
	const struct qmi_elem_info *ei)
{
	const unsigned char *p = data;
	unsigned char seen[32] = { 0 };
	size_t offset = sizeof(struct qmi_header), n;
	unsigned int type;

	if (!data || !ei || len < sizeof(struct qmi_header) ||
	    len > sizeof(struct qmi_header) +
		QMI_IPA_INSTALL_FILTER_RULE_REQ_MAX_MSG_LEN_V01 ||
	    ipa_wire_u16(p + offsetof(struct qmi_header, msg_len)) !=
		len - sizeof(struct qmi_header))
		return -EINVAL;
	while (offset < len) {
		if (len - offset < 3)
			return -EINVAL;
		type = p[offset];
		n = ipa_wire_u16(p + offset + 1);
		if (n > len - offset - 3)
			return -EINVAL;
		if (ipa_wire_known(type, ei)) {
			if (seen[type / 8] & (1U << (type % 8)))
				return -EINVAL;
			seen[type / 8] |= 1U << (type % 8);
		} else if (type < 0x10) {
			return -EINVAL;
		}
		offset += 3 + n;
	}
	return 0;
}

/* Both datagrams have already passed the boundary and duplicate checks. */
static int ipa_wire_contains(const unsigned char *a, size_t alen,
	const unsigned char *b, size_t blen, const struct qmi_elem_info *ei)
{
	size_t x = sizeof(struct qmi_header), y, n, m;
	bool found;

	while (x < alen) {
		n = ipa_wire_u16(a + x + 1);
		if (ipa_wire_known(a[x], ei)) {
			found = false;
			y = sizeof(struct qmi_header);
			while (y < blen) {
				m = ipa_wire_u16(b + y + 1);
				if (a[x] == b[y]) {
					if (n != m || memcmp(a + x + 3, b + y + 3, n))
						return -EINVAL;
					found = true;
					break;
				}
				y += 3 + m;
			}
			if (!found)
				return -EINVAL;
		}
		x += 3 + n;
	}
	return 0;
}

static int ipa_qmi_wire_equal(const void *data, size_t len,
	const void *encoded, size_t encoded_len, const struct qmi_elem_info *ei)
{
	if (ipa_qmi_wire_validate(data, len, ei) ||
	    ipa_qmi_wire_validate(encoded, encoded_len, ei))
		return -EINVAL;
	/* Identity bytes precede msg_len; unknown optional TLVs may change size. */
	if (memcmp(data, encoded, offsetof(struct qmi_header, msg_len)))
		return -EINVAL;
	if (ipa_wire_contains(data, len, encoded, encoded_len, ei) ||
	    ipa_wire_contains(encoded, encoded_len, data, len, ei))
		return -EINVAL;
	return 0;
}

#endif
