[CCode (cheader_filename = "qr-bridge.h")]
namespace QrBridge {
    [CCode (cname = "qr_bridge_decode", array_length = false, array_null_terminated = true)]
    public string[] decode ([CCode (array_length_pos = 1.1)] uint8[] gray, int width, int height);
}
