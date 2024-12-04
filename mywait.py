import signal
import os


def mywait(pid: int, sig: signal.Signals, wnohang: bool = False):
    options = os.WNOHANG if wnohang else 0

    while True:
        _, status = os.waitpid(pid, options)
        if status and os.WIFSTOPPED(status):
            stopped_signal = os.WSTOPSIG(status)

            # Break the loop if the signal is SIGTRAP
            if stopped_signal == sig:
                # print("Breaking out of loop as SIGTRAP was received.")
                return True
            else:
                raise ValueError(
                    f"Signal Raised: {stopped_signal} expected: {sig}")

        if not status:
            return False
