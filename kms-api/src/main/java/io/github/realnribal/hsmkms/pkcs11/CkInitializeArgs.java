package io.github.realnribal.hsmkms.pkcs11;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.List;

public class CkInitializeArgs extends Structure {

    public Pointer createMutex;
    public Pointer destroyMutex;
    public Pointer lockMutex;
    public Pointer unlockMutex;
    public long flags;
    public Pointer reserved;

    @Override
    protected List<String> getFieldOrder() {
        return List.of("createMutex", "destroyMutex", "lockMutex", "unlockMutex", "flags", "reserved");
    }
}
