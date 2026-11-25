package io.github.realnribal.hsmkms.pkcs11;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.List;

public class CK_ATTRIBUTE extends Structure {

    public long type;
    public Pointer pValue;
    public long ulValueLen;

    public CK_ATTRIBUTE() {
    }

    @Override
    protected List<String> getFieldOrder() {
        return List.of("type", "pValue", "ulValueLen");
    }
}
