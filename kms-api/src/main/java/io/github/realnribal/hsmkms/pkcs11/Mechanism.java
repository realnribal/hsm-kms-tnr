package io.github.realnribal.hsmkms.pkcs11;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.List;

public class Mechanism extends Structure {

    public long mechanism;
    public Pointer pParameter;
    public long ulParameterLen;

    /** Holds the parameter bytes so they stay alive for the native call. */
    private Memory owned;

    public static Mechanism of(long type) {
        Mechanism mechanism = new Mechanism();
        mechanism.mechanism = type;
        mechanism.write();
        return mechanism;
    }

    public static Mechanism with(long type, byte[] parameter) {
        Mechanism mechanism = new Mechanism();
        mechanism.mechanism = type;
        mechanism.owned = new Memory(parameter.length);
        mechanism.owned.write(0, parameter, 0, parameter.length);
        mechanism.pParameter = mechanism.owned;
        mechanism.ulParameterLen = parameter.length;
        mechanism.write();
        return mechanism;
    }

    @Override
    protected List<String> getFieldOrder() {
        return List.of("mechanism", "pParameter", "ulParameterLen");
    }
}
