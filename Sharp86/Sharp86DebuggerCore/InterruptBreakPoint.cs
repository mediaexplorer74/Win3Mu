/*
Sharp86 - 8086 Emulator
Copyright (C) 2017-2018 Topten Software.

Sharp86 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Sharp86 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Sharp86.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PetaJson;

namespace Sharp86
{
    public class InterruptBreakPoint : BreakPoint
    {
        public InterruptBreakPoint()
        {
        }

        public InterruptBreakPoint(byte interruptNumber)
        {
            _interruptNumber = interruptNumber;
        }

        [Json("interrupteNumber")]
        byte _interruptNumber;
        public byte InterruptNumber
        {
            get { return _interruptNumber; }
        }

        public override string EditString
        {
            get
            {
                return string.Format("int 0x{0:X2}", _interruptNumber);
            }
        }

        public override bool ShouldBreak(DebuggerCore debugger)
        {
            return false;
        }

        public override string ToString()
        {
            return base.ToString(string.Format("int 0x{0:X2}", _interruptNumber));
        }
    }
}
