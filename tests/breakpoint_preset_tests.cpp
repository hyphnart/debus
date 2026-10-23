#include "BreakpointPreset.h"
#include <QCoreApplication>
#include <QDebug>
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    QVector<BreakpointPreset> input{{0x401000,"RAX",5,1234,true},{0x401100,"ZF",1,0,false}};
    const auto json=BreakpointPresetCodec::encode(input);
    QVector<BreakpointPreset> output;
    QString error;
    if(!BreakpointPresetCodec::decode(json,output,error) || output.size()!=2 ||
       output[0].threadId!=1234 || output[0].address!=0x401000 || !output[0].skipUnmatched ||
       output[1].field!="ZF")return 1;
    const QByteArray bad=R"({"format":"YAS-BREAKPOINT-PRESETS-1","breakpoints":[{"address":"INVALID","field":"ZF","value":"2","threadId":0,"skipUnmatched":true}]})";
    if(BreakpointPresetCodec::decode(bad,output,error))return 2;
    if(output.size()!=2)return 3; // failed decode must not mutate previous output
    qInfo()<<"PASS breakpoint preset codec and input validation";
    return 0;
}
