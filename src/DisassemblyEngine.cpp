#include "DisassemblyEngine.h"
#include <QFile>
#include <algorithm>
#ifdef YAS_HAS_CAPSTONE
#include <capstone/capstone.h>
#endif
DisassemblyReport DisassemblyEngine::decode(const QString &path,quint64 offset,
                                           quint64 virtualAddress,bool x64,int maxInstructions) {
    DisassemblyReport r; r.startAddress=virtualAddress;
#ifndef YAS_HAS_CAPSTONE
    Q_UNUSED(path); Q_UNUSED(offset); Q_UNUSED(x64); Q_UNUSED(maxInstructions);
    r.error="Capstone was not found at build time. Install Capstone and reconfigure CMake.";
    return r;
#else
    QFile f(path);
    if(!f.open(QIODevice::ReadOnly)) {r.error=f.errorString();return r;}
    if(offset>=static_cast<quint64>(f.size())) {r.error="Offset is outside the file.";return r;}
    if(!f.seek(static_cast<qint64>(offset))) {r.error="Cannot seek to offset.";return r;}
    // Read at most 64 KiB; no unbounded allocation on untrusted files.
    QByteArray data=f.read(65536);
    if(data.isEmpty()) {r.error="No bytes available.";return r;}
    csh handle=0;
    if(cs_open(CS_ARCH_X86,x64?CS_MODE_64:CS_MODE_32,&handle)!=CS_ERR_OK) {
        r.error="Cannot initialize Capstone.";return r;
    }
    cs_option(handle,CS_OPT_DETAIL,CS_OPT_OFF);
    cs_insn *instructions=nullptr;
    const size_t count=cs_disasm(handle,
        reinterpret_cast<const uint8_t*>(data.constData()),static_cast<size_t>(data.size()),
        virtualAddress,static_cast<size_t>(std::clamp(maxInstructions,1,2000)),&instructions);
    r.available=true;
    if(count==0) r.error="No decodable instructions at this offset.";
    for(size_t i=0;i<count;++i) {
        const cs_insn &ins=instructions[i];
        Instruction out;out.address=ins.address;
        out.bytes=QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(ins.bytes),ins.size).toHex(' ').toUpper());
        out.mnemonic=QString::fromLatin1(ins.mnemonic);
        out.operands=QString::fromLatin1(ins.op_str);
        r.instructions.append(out);
    }
    if(instructions) cs_free(instructions,count);
    cs_close(&handle);
    return r;
#endif
}
