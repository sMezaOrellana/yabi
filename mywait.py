import signal

import os


def mywait(pid: int, sig: signal.Signals):
    while True:
        _, status = os.waitpid(pid, 0)
        if os.WIFSTOPPED(status):
            stopped_signal = os.WSTOPSIG(status)
            print(f"Child process {pid} stopped by signal {stopped_signal}")

            # Break the loop if the signal is SIGTRAP
            if stopped_signal == sig:
                print("Breaking out of loop as SIGTRAP was received.")
                break
            else:
                raise ValueError(
                    f"Signal Raised: {stopped_signal} expected: {sig}")

    return True
