package io.github.realnribal.hsmkms.hsm;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.LongByReference;
import io.github.realnribal.hsmkms.pkcs11.Attributes;
import io.github.realnribal.hsmkms.pkcs11.CK_ATTRIBUTE;
import io.github.realnribal.hsmkms.pkcs11.Ck;
import io.github.realnribal.hsmkms.pkcs11.CkException;
import io.github.realnribal.hsmkms.pkcs11.CkInitializeArgs;
import io.github.realnribal.hsmkms.pkcs11.Cryptoki;
import io.github.realnribal.hsmkms.pkcs11.Mechanism;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * One read-write session on the lab token. SoftHSM keeps a process-wide login, so every call is serialized
 * and a PIN probe logs out before it tries the candidate PIN.
 */
public final class TokenClient implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(TokenClient.class);
    private static final List<String> USAGE_ORDER = List.of(
            "ENCRYPT", "DECRYPT", "WRAP", "UNWRAP", "SIGN", "VERIFY");

    private final Cryptoki cryptoki;
    private final CkInitializeArgs initArgs;
    private final ReentrantLock lock = new ReentrantLock();
    private final String libraryPath;
    private final byte[] userPin;
    private final String cryptokiVersion;
    private final String manufacturerId;
    private final String libraryDescription;
    private long slotId;
    private long session;
    private boolean closed;

    private TokenClient(
            Cryptoki cryptoki,
            CkInitializeArgs initArgs,
            String libraryPath,
            byte[] userPin,
            String cryptokiVersion,
            String manufacturerId,
            String libraryDescription,
            long slotId,
            long session) {
        this.cryptoki = cryptoki;
        this.initArgs = initArgs;
        this.libraryPath = libraryPath;
        this.userPin = userPin;
        this.cryptokiVersion = cryptokiVersion;
        this.manufacturerId = manufacturerId;
        this.libraryDescription = libraryDescription;
        this.slotId = slotId;
        this.session = session;
    }

    public static TokenClient open(String libraryPath, String tokenLabel, String userPin) {
        if (NativeLong.SIZE != 8) {
            throw new IllegalStateException("PKCS#11 binding requires LP64 (NativeLong.SIZE=" + NativeLong.SIZE + ")");
        }
        if (new CK_ATTRIBUTE().size() != 24 || Mechanism.of(0).size() != 24 || new CkInitializeArgs().size() != 48) {
            throw new IllegalStateException("Unexpected PKCS#11 structure layout");
        }
        Cryptoki cryptoki = Native.load(libraryPath, Cryptoki.class);
        CkInitializeArgs args = new CkInitializeArgs();
        args.flags = Ck.CKF_OS_LOCKING_OK;
        args.write();
        long rv = cryptoki.C_Initialize(args);
        if (rv != Ck.CKR_OK && rv != Ck.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
            throw new CkException(rv, "C_Initialize");
        }
        Memory info = new Memory(256);
        check(cryptoki.C_GetInfo(info), "C_GetInfo");
        String version = (info.getByte(0) & 0xff) + "." + (info.getByte(1) & 0xff);
        String manufacturer = fixed(info, 2, 32);
        String description = printable(fixed(info, 48, 32));

        long slot = findSlot(cryptoki, tokenLabel);
        LongByReference sessionRef = new LongByReference();
        check(cryptoki.C_OpenSession(slot, Ck.CKF_SERIAL_SESSION | Ck.CKF_RW_SESSION, null, null, sessionRef),
                "C_OpenSession");
        byte[] pin = userPin.getBytes(StandardCharsets.UTF_8);
        rv = cryptoki.C_Login(sessionRef.getValue(), Ck.CKU_USER, pin, pin.length);
        if (rv != Ck.CKR_OK) {
            cryptoki.C_CloseSession(sessionRef.getValue());
            throw new CkException(rv, "C_Login (check HSM_PIN against scripts/init-token.sh)");
        }
        log.info("pkcs11 ready library={} cryptoki={} manufacturer={} token={} slot={}",
                libraryPath, version, manufacturer, tokenLabel, slot);
        return new TokenClient(cryptoki, args, libraryPath, pin, version, manufacturer, description, slot,
                sessionRef.getValue());
    }

    public TokenInfo info() {
        return withLock(() -> {
            Memory raw = new Memory(512);
            check(cryptoki.C_GetTokenInfo(slotId, raw), "C_GetTokenInfo");
            return new TokenInfo(
                    libraryPath,
                    cryptokiVersion,
                    manufacturerId,
                    libraryDescription,
                    fixed(raw, 0, 32),
                    fixed(raw, 32, 32),
                    fixed(raw, 64, 16),
                    fixed(raw, 80, 16));
        });
    }

    public StoredKey createAes(String alias, int sizeBits, KeyUse use) {
        return withLock(() -> {
            rejectDuplicate(alias);
            Attributes template = secretTemplate(alias, Ck.CKK_AES, sizeBits / 8L, use);
            generateKey(template, Mechanism.of(Ck.CKM_AES_KEY_GEN));
            return describeLabel(alias);
        });
    }

    public StoredKey createRsa(String alias, int sizeBits, KeyUse use) {
        return withLock(() -> {
            rejectDuplicate(alias);
            byte[] label = alias.getBytes(StandardCharsets.UTF_8);
            Attributes pub = new Attributes()
                    .bool(Ck.CKA_TOKEN, true)
                    .bool(Ck.CKA_VERIFY, use.verify())
                    .bool(Ck.CKA_WRAP, use.wrap())
                    .ulong(Ck.CKA_MODULUS_BITS, sizeBits)
                    .bytes(Ck.CKA_PUBLIC_EXPONENT, Ck.RSA_PUBLIC_EXPONENT)
                    .bytes(Ck.CKA_LABEL, label)
                    .bytes(Ck.CKA_ID, label);
            Attributes priv = new Attributes()
                    .bool(Ck.CKA_TOKEN, true)
                    .bool(Ck.CKA_PRIVATE, true)
                    .bool(Ck.CKA_SENSITIVE, true)
                    .bool(Ck.CKA_EXTRACTABLE, false)
                    .bool(Ck.CKA_SIGN, use.sign())
                    .bool(Ck.CKA_UNWRAP, use.unwrap())
                    .bytes(Ck.CKA_LABEL, label)
                    .bytes(Ck.CKA_ID, label);
            generatePair(Mechanism.of(Ck.CKM_RSA_PKCS_KEY_PAIR_GEN), pub, priv);
            return describeLabel(alias);
        });
    }

    public StoredKey createEc(String alias, KeyUse use) {
        return withLock(() -> {
            rejectDuplicate(alias);
            byte[] label = alias.getBytes(StandardCharsets.UTF_8);
            Attributes pub = new Attributes()
                    .bool(Ck.CKA_TOKEN, true)
                    .bool(Ck.CKA_VERIFY, use.verify())
                    .bytes(Ck.CKA_EC_PARAMS, Ck.SECP256R1)
                    .bytes(Ck.CKA_LABEL, label)
                    .bytes(Ck.CKA_ID, label);
            Attributes priv = new Attributes()
                    .bool(Ck.CKA_TOKEN, true)
                    .bool(Ck.CKA_PRIVATE, true)
                    .bool(Ck.CKA_SENSITIVE, true)
                    .bool(Ck.CKA_EXTRACTABLE, false)
                    .bool(Ck.CKA_SIGN, use.sign())
                    .bytes(Ck.CKA_LABEL, label)
                    .bytes(Ck.CKA_ID, label);
            generatePair(Mechanism.of(Ck.CKM_EC_KEY_PAIR_GEN), pub, priv);
            return describeLabel(alias);
        });
    }

    public List<StoredKey> list() {
        return withLock(() -> describeAll(find(new Attributes().bool(Ck.CKA_TOKEN, true))));
    }

    public StoredKey require(String alias) {
        return withLock(() -> describeLabel(alias));
    }

    public void delete(String alias) {
        withLock(() -> {
            List<Long> handles = findByLabel(alias);
            if (handles.isEmpty()) {
                throw new KeyNotFoundException(alias);
            }
            for (long handle : handles) {
                check(cryptoki.C_DestroyObject(session, handle), "C_DestroyObject");
            }
            return null;
        });
    }

    public byte[] encrypt(String alias, byte[] iv, byte[] plaintext) {
        return withLock(() -> {
            long key = requireClass(alias, Ck.CKO_SECRET_KEY);
            Mechanism mechanism = Mechanism.with(Ck.CKM_AES_CBC_PAD, iv);
            check(cryptoki.C_EncryptInit(session, mechanism, key), "C_EncryptInit");
            byte[] out = new byte[plaintext.length + 32];
            LongByReference len = new LongByReference(out.length);
            check(cryptoki.C_Encrypt(session, plaintext, plaintext.length, out, len), "C_Encrypt");
            return Arrays.copyOf(out, lengthOf(len, out.length));
        });
    }

    public byte[] decrypt(String alias, byte[] iv, byte[] ciphertext) {
        return withLock(() -> {
            long key = requireClass(alias, Ck.CKO_SECRET_KEY);
            Mechanism mechanism = Mechanism.with(Ck.CKM_AES_CBC_PAD, iv);
            check(cryptoki.C_DecryptInit(session, mechanism, key), "C_DecryptInit");
            byte[] out = new byte[ciphertext.length + 32];
            LongByReference len = new LongByReference(out.length);
            check(cryptoki.C_Decrypt(session, ciphertext, ciphertext.length, out, len), "C_Decrypt");
            return Arrays.copyOf(out, lengthOf(len, out.length));
        });
    }

    /**
     * Asks the token to sign with whatever key object the alias names. Returns the raw CK_RV.
     * Used by the negative campaign to show the token, not only the API, rejects a bad mechanism.
     */
    public long signAttempt(String alias, long mechanismId, byte[] data) {
        return withLock(() -> {
            List<Long> secret = findClass(alias, Ck.CKO_SECRET_KEY);
            long key = secret.isEmpty() ? requireClass(alias, Ck.CKO_PRIVATE_KEY) : secret.get(0);
            Mechanism mechanism = Mechanism.of(mechanismId);
            long rv = cryptoki.C_SignInit(session, mechanism, key);
            if (rv != Ck.CKR_OK) {
                return rv;
            }
            byte[] signature = new byte[256];
            LongByReference len = new LongByReference(signature.length);
            return cryptoki.C_Sign(session, data, data.length, signature, len);
        });
    }

    public byte[] sign(String alias, long mechanismId, byte[] data, int signatureSize) {
        return withLock(() -> {
            long key = requireClass(alias, Ck.CKO_PRIVATE_KEY);
            Mechanism mechanism = Mechanism.of(mechanismId);
            check(cryptoki.C_SignInit(session, mechanism, key), "C_SignInit");
            byte[] signature = new byte[signatureSize];
            LongByReference len = new LongByReference(signature.length);
            check(cryptoki.C_Sign(session, data, data.length, signature, len), "C_Sign");
            return Arrays.copyOf(signature, lengthOf(len, signature.length));
        });
    }

    public boolean verify(String alias, long mechanismId, byte[] data, byte[] signature) {
        return withLock(() -> {
            long key = requireClass(alias, Ck.CKO_PUBLIC_KEY);
            Mechanism mechanism = Mechanism.of(mechanismId);
            check(cryptoki.C_VerifyInit(session, mechanism, key), "C_VerifyInit");
            long rv = cryptoki.C_Verify(session, data, data.length, signature, signature.length);
            if (rv == Ck.CKR_SIGNATURE_INVALID || rv == Ck.CKR_SIGNATURE_LEN_RANGE) {
                return false;
            }
            check(rv, "C_Verify");
            return true;
        });
    }

    public byte[] wrap(String wrappingAlias, long mechanismId, String targetAlias, boolean rsa) {
        return withLock(() -> {
            long wrapping = requireClass(wrappingAlias, rsa ? Ck.CKO_PUBLIC_KEY : Ck.CKO_SECRET_KEY);
            long target = requireClass(targetAlias, Ck.CKO_SECRET_KEY);
            Mechanism mechanism = Mechanism.of(mechanismId);
            byte[] buffer = new byte[rsa ? 512 : 256];
            LongByReference len = new LongByReference(buffer.length);
            check(cryptoki.C_WrapKey(session, mechanism, wrapping, target, buffer, len), "C_WrapKey");
            return Arrays.copyOf(buffer, lengthOf(len, buffer.length));
        });
    }

    public StoredKey unwrapAes(String wrappingAlias, long mechanismId, byte[] wrapped, String targetAlias, KeyUse use,
                               boolean rsa) {
        return withLock(() -> {
            rejectDuplicate(targetAlias);
            long unwrapping = requireClass(wrappingAlias, rsa ? Ck.CKO_PRIVATE_KEY : Ck.CKO_SECRET_KEY);
            byte[] label = targetAlias.getBytes(StandardCharsets.UTF_8);
            // SoftHSM rejects CKA_VALUE_LEN on C_UnwrapKey (CKR_ATTRIBUTE_READ_ONLY) and does not
            // report it afterwards. The key length is proven by using the unwrapped key.
            Attributes template = new Attributes()
                    .ulong(Ck.CKA_CLASS, Ck.CKO_SECRET_KEY)
                    .ulong(Ck.CKA_KEY_TYPE, Ck.CKK_AES)
                    .bool(Ck.CKA_TOKEN, true)
                    .bool(Ck.CKA_PRIVATE, true)
                    .bool(Ck.CKA_SENSITIVE, true)
                    .bool(Ck.CKA_EXTRACTABLE, use.extractable())
                    .bool(Ck.CKA_ENCRYPT, use.encrypt())
                    .bool(Ck.CKA_DECRYPT, use.decrypt())
                    .bool(Ck.CKA_WRAP, use.wrap())
                    .bool(Ck.CKA_UNWRAP, use.unwrap())
                    .bytes(Ck.CKA_LABEL, label)
                    .bytes(Ck.CKA_ID, label);
            Mechanism mechanism = Mechanism.of(mechanismId);
            LongByReference handle = new LongByReference();
            CK_ATTRIBUTE[] array = template.array();
            check(cryptoki.C_UnwrapKey(session, mechanism, unwrapping, wrapped, wrapped.length, array, array.length, handle),
                    "C_UnwrapKey");
            return describeLabel(targetAlias);
        });
    }

    /**
     * SoftHSM login state is process-wide. Log out, try the candidate, then restore the lab PIN.
     * The candidate PIN is never written to the log.
     */
    public long probeUserPin(String candidate) {
        return withLock(() -> {
            long logout = cryptoki.C_Logout(session);
            if (logout != Ck.CKR_OK && logout != Ck.CKR_USER_NOT_LOGGED_IN) {
                throw new CkException(logout, "C_Logout");
            }
            byte[] probe = candidate.getBytes(StandardCharsets.UTF_8);
            long rv;
            try {
                rv = cryptoki.C_Login(session, Ck.CKU_USER, probe, probe.length);
            } finally {
                Arrays.fill(probe, (byte) 0);
            }
            if (rv == Ck.CKR_OK) {
                cryptoki.C_Logout(session);
            }
            long restore = cryptoki.C_Login(session, Ck.CKU_USER, userPin, userPin.length);
            if (restore != Ck.CKR_OK) {
                throw new CkException(restore, "C_Login restore after PIN probe");
            }
            log.info("op=probePin ckR={}", Ck.name(rv));
            return rv;
        });
    }

    public long attributeRv(String alias, long attribute) {
        return withLock(() -> {
            long handle = firstHandle(alias);
            Memory memory = new Memory(64);
            CK_ATTRIBUTE full = new CK_ATTRIBUTE();
            full.type = attribute;
            full.pValue = memory;
            full.ulValueLen = memory.size();
            full.write();
            return cryptoki.C_GetAttributeValue(session, handle, full, 1);
        });
    }

    @Override
    public void close() {
        lock.lock();
        try {
            if (closed) {
                return;
            }
            closed = true;
            if (session != 0) {
                cryptoki.C_Logout(session);
                cryptoki.C_CloseSession(session);
                session = 0;
            }
            // initArgs stays reachable until Finalize so the library does not observe a freed CK_C_INITIALIZE_ARGS.
            cryptoki.C_Finalize(null);
            log.info("pkcs11 session closed initBytes={}", initArgs.size());
        } finally {
            lock.unlock();
        }
    }

    private void generateKey(Attributes template, Mechanism mechanism) {
        LongByReference handle = new LongByReference();
        CK_ATTRIBUTE[] array = template.array();
        check(cryptoki.C_GenerateKey(session, mechanism, array, array.length, handle), "C_GenerateKey");
    }

    private void generatePair(Mechanism mechanism, Attributes pub, Attributes priv) {
        CK_ATTRIBUTE[] publicTemplate = pub.array();
        CK_ATTRIBUTE[] privateTemplate = priv.array();
        LongByReference publicKey = new LongByReference();
        LongByReference privateKey = new LongByReference();
        check(cryptoki.C_GenerateKeyPair(
                session, mechanism, publicTemplate, publicTemplate.length, privateTemplate, privateTemplate.length,
                publicKey, privateKey), "C_GenerateKeyPair");
    }

    private Attributes secretTemplate(String alias, long keyType, long valueLen, KeyUse use) {
        byte[] label = alias.getBytes(StandardCharsets.UTF_8);
        return new Attributes()
                .ulong(Ck.CKA_CLASS, Ck.CKO_SECRET_KEY)
                .ulong(Ck.CKA_KEY_TYPE, keyType)
                .ulong(Ck.CKA_VALUE_LEN, valueLen)
                .bool(Ck.CKA_TOKEN, true)
                .bool(Ck.CKA_PRIVATE, true)
                .bool(Ck.CKA_SENSITIVE, true)
                .bool(Ck.CKA_EXTRACTABLE, use.extractable())
                .bool(Ck.CKA_ENCRYPT, use.encrypt())
                .bool(Ck.CKA_DECRYPT, use.decrypt())
                .bool(Ck.CKA_WRAP, use.wrap())
                .bool(Ck.CKA_UNWRAP, use.unwrap())
                .bytes(Ck.CKA_LABEL, label)
                .bytes(Ck.CKA_ID, label);
    }

    private void rejectDuplicate(String alias) {
        if (!findByLabel(alias).isEmpty()) {
            throw new DuplicateAliasException(alias);
        }
    }

    private long requireClass(String alias, long objectClass) {
        List<Long> handles = findClass(alias, objectClass);
        if (handles.isEmpty()) {
            throw new KeyNotFoundException(alias);
        }
        return handles.get(0);
    }

    private long firstHandle(String alias) {
        List<Long> secret = findClass(alias, Ck.CKO_SECRET_KEY);
        if (!secret.isEmpty()) {
            return secret.get(0);
        }
        List<Long> priv = findClass(alias, Ck.CKO_PRIVATE_KEY);
        if (!priv.isEmpty()) {
            return priv.get(0);
        }
        throw new KeyNotFoundException(alias);
    }

    private List<Long> findByLabel(String alias) {
        return find(new Attributes().bytes(Ck.CKA_LABEL, alias.getBytes(StandardCharsets.UTF_8)));
    }

    private List<Long> findClass(String alias, long objectClass) {
        return find(new Attributes()
                .bytes(Ck.CKA_LABEL, alias.getBytes(StandardCharsets.UTF_8))
                .ulong(Ck.CKA_CLASS, objectClass));
    }

    private List<Long> find(Attributes template) {
        CK_ATTRIBUTE[] array = template.array();
        check(cryptoki.C_FindObjectsInit(session, array, array.length), "C_FindObjectsInit");
        try {
            List<Long> handles = new ArrayList<>();
            Memory buffer = new Memory(32L * 8);
            while (true) {
                LongByReference count = new LongByReference();
                check(cryptoki.C_FindObjects(session, buffer, 32, count), "C_FindObjects");
                int n = (int) count.getValue();
                for (int i = 0; i < n; i++) {
                    handles.add(buffer.getLong((long) i * 8));
                }
                if (n < 32) {
                    return handles;
                }
            }
        } finally {
            cryptoki.C_FindObjectsFinal(session);
        }
    }

    private StoredKey describeLabel(String alias) {
        List<StoredKey> keys = describeAll(findByLabel(alias));
        if (keys.isEmpty()) {
            throw new KeyNotFoundException(alias);
        }
        return keys.get(0);
    }

    private List<StoredKey> describeAll(List<Long> handles) {
        Map<String, List<RawObject>> grouped = new LinkedHashMap<>();
        for (long handle : handles) {
            RawObject raw = describe(handle);
            if (raw.label.isEmpty()) {
                continue;
            }
            grouped.computeIfAbsent(raw.label, ignored -> new ArrayList<>()).add(raw);
        }
        List<StoredKey> keys = new ArrayList<>();
        for (List<RawObject> objects : grouped.values()) {
            keys.add(toStored(objects));
        }
        keys.sort(Comparator.comparing(StoredKey::alias));
        return keys;
    }

    private RawObject describe(long handle) {
        RawObject raw = new RawObject();
        raw.handle = handle;
        raw.clazz = ulongAttr(handle, Ck.CKA_CLASS).orElse(-1L);
        raw.keyType = ulongAttr(handle, Ck.CKA_KEY_TYPE).orElse(-1L);
        raw.label = tryAttr(handle, Ck.CKA_LABEL)
                .map(bytes -> new String(bytes, StandardCharsets.UTF_8).trim())
                .orElse("");
        raw.token = flag(handle, Ck.CKA_TOKEN);
        raw.sensitive = flag(handle, Ck.CKA_SENSITIVE);
        raw.extractable = flag(handle, Ck.CKA_EXTRACTABLE);
        raw.encrypt = flag(handle, Ck.CKA_ENCRYPT);
        raw.decrypt = flag(handle, Ck.CKA_DECRYPT);
        raw.wrap = flag(handle, Ck.CKA_WRAP);
        raw.unwrap = flag(handle, Ck.CKA_UNWRAP);
        raw.sign = flag(handle, Ck.CKA_SIGN);
        raw.verify = flag(handle, Ck.CKA_VERIFY);
        raw.valueLen = ulongAttr(handle, Ck.CKA_VALUE_LEN).orElse(0L);
        raw.modulusBits = ulongAttr(handle, Ck.CKA_MODULUS_BITS).orElse(0L);
        raw.ecParams = tryAttr(handle, Ck.CKA_EC_PARAMS).orElse(null);
        return raw;
    }

    private StoredKey toStored(List<RawObject> objects) {
        RawObject secret = objects.stream().filter(o -> o.clazz == Ck.CKO_SECRET_KEY).findFirst().orElse(null);
        RawObject priv = objects.stream().filter(o -> o.clazz == Ck.CKO_PRIVATE_KEY).findFirst().orElse(null);
        RawObject pub = objects.stream().filter(o -> o.clazz == Ck.CKO_PUBLIC_KEY).findFirst().orElse(null);
        RawObject primary = secret != null ? secret : (priv != null ? priv : pub);
        String algorithm = algorithmOf(primary.keyType);
        String curve = null;
        int sizeBits = 0;
        if ("AES".equals(algorithm)) {
            sizeBits = (int) (primary.valueLen * 8);
        } else if ("RSA".equals(algorithm)) {
            RawObject sized = pub != null && pub.modulusBits > 0 ? pub : primary;
            sizeBits = (int) sized.modulusBits;
        } else if ("EC".equals(algorithm)) {
            sizeBits = 256;
            byte[] params = pub != null && pub.ecParams != null ? pub.ecParams : primary.ecParams;
            if (params != null && Arrays.equals(params, Ck.SECP256R1)) {
                curve = "secp256r1";
            }
        }
        boolean sensitive = secret != null ? secret.sensitive : priv != null && priv.sensitive;
        boolean extractable = secret != null ? secret.extractable : priv != null && priv.extractable;
        boolean token = primary.token;
        return new StoredKey(
                primary.label,
                algorithm,
                secret != null ? "SECRET" : "KEY_PAIR",
                sizeBits,
                curve,
                sensitive,
                extractable,
                token,
                usagesOf(objects));
    }

    private static List<String> usagesOf(List<RawObject> objects) {
        boolean encrypt = false;
        boolean decrypt = false;
        boolean wrap = false;
        boolean unwrap = false;
        boolean sign = false;
        boolean verify = false;
        for (RawObject object : objects) {
            encrypt |= object.encrypt;
            decrypt |= object.decrypt;
            wrap |= object.wrap;
            unwrap |= object.unwrap;
            sign |= object.sign;
            verify |= object.verify;
        }
        List<String> usages = new ArrayList<>();
        if (encrypt) usages.add("ENCRYPT");
        if (decrypt) usages.add("DECRYPT");
        if (wrap) usages.add("WRAP");
        if (unwrap) usages.add("UNWRAP");
        if (sign) usages.add("SIGN");
        if (verify) usages.add("VERIFY");
        usages.sort(Comparator.comparingInt(USAGE_ORDER::indexOf));
        return List.copyOf(usages);
    }

    private static String algorithmOf(long keyType) {
        if (keyType == Ck.CKK_AES) return "AES";
        if (keyType == Ck.CKK_RSA) return "RSA";
        if (keyType == Ck.CKK_EC) return "EC";
        return "UNKNOWN";
    }

    private boolean flag(long handle, long type) {
        return tryAttr(handle, type).map(raw -> raw.length > 0 && raw[0] != 0).orElse(false);
    }

    private Optional<Long> ulongAttr(long handle, long type) {
        Optional<byte[]> raw = tryAttr(handle, type);
        if (raw.isEmpty() || raw.get().length != 8) {
            return Optional.empty();
        }
        Memory memory = new Memory(8);
        memory.write(0, raw.get(), 0, 8);
        return Optional.of(memory.getLong(0));
    }

    private Optional<byte[]> tryAttr(long handle, long type) {
        CK_ATTRIBUTE probe = new CK_ATTRIBUTE();
        probe.type = type;
        probe.pValue = null;
        probe.ulValueLen = 0;
        probe.write();
        long rv = cryptoki.C_GetAttributeValue(session, handle, probe, 1);
        probe.read();
        if (rv != Ck.CKR_OK || probe.ulValueLen <= 0 || probe.ulValueLen > 8192) {
            return Optional.empty();
        }
        Memory memory = new Memory(probe.ulValueLen);
        CK_ATTRIBUTE full = new CK_ATTRIBUTE();
        full.type = type;
        full.pValue = memory;
        full.ulValueLen = probe.ulValueLen;
        full.write();
        rv = cryptoki.C_GetAttributeValue(session, handle, full, 1);
        if (rv != Ck.CKR_OK) {
            return Optional.empty();
        }
        return Optional.of(memory.getByteArray(0, (int) probe.ulValueLen));
    }

    private <T> T withLock(Supplier<T> work) {
        lock.lock();
        try {
            if (closed) {
                throw new IllegalStateException("PKCS#11 session is closed");
            }
            return work.get();
        } finally {
            lock.unlock();
        }
    }

    private static int lengthOf(LongByReference len, int capacity) {
        int n = (int) len.getValue();
        if (n <= 0 || n > capacity) {
            return capacity;
        }
        return n;
    }

    private static long findSlot(Cryptoki cryptoki, String tokenLabel) {
        LongByReference countRef = new LongByReference();
        check(cryptoki.C_GetSlotList((byte) 1, null, countRef), "C_GetSlotList");
        int count = (int) countRef.getValue();
        if (count <= 0) {
            throw new IllegalStateException("No PKCS#11 token is present. Run scripts/init-token.sh.");
        }
        Memory slots = new Memory((long) count * 8);
        countRef.setValue(count);
        check(cryptoki.C_GetSlotList((byte) 1, slots, countRef), "C_GetSlotList");
        List<String> seen = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            long slot = slots.getLong((long) i * 8);
            Memory raw = new Memory(512);
            long rv = cryptoki.C_GetTokenInfo(slot, raw);
            if (rv != Ck.CKR_OK) {
                continue;
            }
            String label = fixed(raw, 0, 32);
            seen.add(label.isEmpty() ? "(unlabelled)" : label);
            if (label.equals(tokenLabel)) {
                return slot;
            }
        }
        throw new IllegalStateException("Token '" + tokenLabel + "' not found. Visible tokens: " + seen);
    }

    private static void check(long rv, String operation) {
        if (rv != Ck.CKR_OK) {
            throw new CkException(rv, operation);
        }
    }

    private static String fixed(Memory memory, int offset, int length) {
        byte[] raw = memory.getByteArray(offset, length);
        int end = raw.length;
        while (end > 0 && (raw[end - 1] == ' ' || raw[end - 1] == 0)) {
            end--;
        }
        return new String(raw, 0, end, StandardCharsets.UTF_8).trim();
    }

    private static String printable(String value) {
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch < 32 || ch > 126) {
                return "";
            }
        }
        return value;
    }

    private static final class RawObject {
        private long handle;
        private long clazz;
        private long keyType;
        private String label;
        private boolean token;
        private boolean sensitive;
        private boolean extractable;
        private boolean encrypt;
        private boolean decrypt;
        private boolean wrap;
        private boolean unwrap;
        private boolean sign;
        private boolean verify;
        private long valueLen;
        private long modulusBits;
        private byte[] ecParams;
    }
}
