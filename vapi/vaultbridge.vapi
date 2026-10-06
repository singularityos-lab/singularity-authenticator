[CCode (cheader_filename = "vault-bridge.h")]
namespace VaultBridge {
    [CCode (cname = "vault_bridge_scrypt")]
    public bool scrypt ([CCode (array_length_type = "gsize")] uint8[] password, [CCode (array_length_type = "gsize")] uint8[] salt, uint64 n, int r, int p, [CCode (array_length_type = "gsize")] uint8[] key);
    [CCode (cname = "vault_bridge_seal")]
    public bool seal ([CCode (array_length_type = "gsize")] uint8[] key, [CCode (array_length_type = "gsize")] uint8[] nonce, [CCode (array_length_type = "gsize")] uint8[] plain, [CCode (array_length_type = "gsize")] uint8[] cipher, [CCode (array_length_type = "gsize")] uint8[] tag);
    [CCode (cname = "vault_bridge_open")]
    public bool open ([CCode (array_length_type = "gsize")] uint8[] key, [CCode (array_length_type = "gsize")] uint8[] nonce, [CCode (array_length_type = "gsize")] uint8[] cipher, [CCode (array_length_type = "gsize")] uint8[] tag, [CCode (array_length_type = "gsize")] uint8[] plain);
    [CCode (cname = "vault_bridge_random")]
    public void random ([CCode (array_length_type = "gsize")] uint8[] buffer);
}
