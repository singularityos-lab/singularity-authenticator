namespace Singularity.Apps.Authenticator {

    namespace Qr {
        public const bool AVAILABLE = false;

        public string[] decode_file (string path) throws Error {
            throw new IOError.NOT_SUPPORTED (_("Reading QR codes needs the ZBar library."));
        }
    }
}
