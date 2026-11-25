package io.github.realnribal.hsmkms.pkcs11;

import com.sun.jna.Memory;

import java.util.ArrayList;
import java.util.List;

/**
 * Builds a contiguous {@link CK_ATTRIBUTE} array. Keep the instance reachable until the PKCS#11 call returns:
 * the value buffers live here.
 */
public final class Attributes {

    private final List<Item> items = new ArrayList<>();

    public Attributes ulong(long type, long value) {
        Memory memory = new Memory(8);
        memory.setLong(0, value);
        items.add(new Item(type, memory, 8));
        return this;
    }

    public Attributes bool(long type, boolean value) {
        Memory memory = new Memory(1);
        memory.setByte(0, (byte) (value ? 1 : 0));
        items.add(new Item(type, memory, 1));
        return this;
    }

    public Attributes bytes(long type, byte[] value) {
        Memory memory = new Memory(Math.max(value.length, 1));
        if (value.length > 0) {
            memory.write(0, value, 0, value.length);
        }
        items.add(new Item(type, memory, value.length));
        return this;
    }

    public CK_ATTRIBUTE[] array() {
        if (items.isEmpty()) {
            throw new IllegalStateException("empty attribute template");
        }
        CK_ATTRIBUTE[] array = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(items.size());
        for (int i = 0; i < items.size(); i++) {
            Item item = items.get(i);
            array[i].type = item.type;
            array[i].pValue = item.memory;
            array[i].ulValueLen = item.length;
            array[i].write();
        }
        return array;
    }

    private record Item(long type, Memory memory, long length) {
    }
}
