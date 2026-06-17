using System;

namespace Cda.Core.Model
{
    /// <summary>
    /// Architecture-neutral replacement for the legacy <c>oSingleData</c> record.
    /// Every address/register is widened to <see cref="ulong"/> so one record
    /// type describes a call captured from a 32-bit or 64-bit target. How the
    /// captured values map to a calling convention is the job of the
    /// architecture decoder (see <c>Cda.Core.Cpu</c>), not of this record.
    /// </summary>
    public sealed class CallRecord
    {
        /// <summary>Seconds since the start of the trace.</summary>
        public double Time;

        /// <summary>Address of the call site (caller / return address region).</summary>
        public ulong Source;

        /// <summary>Address of the callee that was entered.</summary>
        public ulong Destination;

        /// <summary>Stack pointer at entry (ESP on x86, RSP on x64).</summary>
        public ulong StackPointer;

        /// <summary>
        /// Raw stack words captured at entry, from the stack pointer upward (each
        /// zero-extended to 64-bit). Used host-side to walk past runtime/CRT
        /// wrappers back to the caller in the program's own code. May be empty.
        /// </summary>
        public ulong[] StackSnapshot = Array.Empty<ulong>();

        /// <summary>
        /// Captured integer argument values in calling-convention order. On x86
        /// these are the ecx/edx/eax shadow plus stack slots; on x64 these are
        /// RCX/RDX/R8/R9 followed by stack spill slots. May be empty.
        /// </summary>
        public ulong[] IntegerArgs = Array.Empty<ulong>();

        /// <summary>Pointer-follow captures (strings, structures) for arguments.</summary>
        public Dereference[] Dereferences = Array.Empty<Dereference>();

        public CallRecord() { }

        public CallRecord(double time, ulong source, ulong destination)
        {
            Time = time;
            Source = source;
            Destination = destination;
        }
    }
}
