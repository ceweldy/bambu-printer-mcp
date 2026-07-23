export function redactPrinterConnectionError(error) {
    const message = error instanceof Error ? error.message : String(error ?? "");
    if (/auth|unauthor|access denied|bad credential/i.test(message)) {
        return "Printer authentication failed.";
    }
    if (/timed? out|timeout/i.test(message)) {
        return "Printer connection timed out.";
    }
    if (/refused|econnrefused/i.test(message)) {
        return "Printer connection was refused.";
    }
    if (/unreach|enotfound|ehostunreach|enetunreach/i.test(message)) {
        return "Printer is unreachable.";
    }
    return "Printer status is unavailable.";
}
