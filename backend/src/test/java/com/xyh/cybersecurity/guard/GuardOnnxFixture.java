package com.xyh.cybersecurity.guard;

import java.io.ByteArrayOutputStream;
import java.nio.*;
import java.nio.charset.StandardCharsets;

/** 测试期生成的固定常量 ONNX，仅验证入口/策略 plumbing，不是训练候选或模型准确率证据。 */
final class GuardOnnxFixture {
    static byte[] model(float score){
        return model(score,score,0,0,0);
    }
    static byte[] model(float score,float... families){
        byte[] attackTensor=concat(integer(1,1),integer(1,1),integer(2,1),bytes(9,ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putFloat(score).array()));
        byte[] familyTensor=concat(integer(1,1),integer(1,families.length),integer(2,1),bytes(9,floats(families)));
        byte[] attackAttr=concat(text(1,"value"),integer(20,4),bytes(5,attackTensor));
        byte[] familyAttr=concat(text(1,"value"),integer(20,4),bytes(5,familyTensor));
        byte[] attackNode=concat(text(2,"attack_score"),text(4,"Constant"),bytes(5,attackAttr));
        byte[] familyNode=concat(text(2,"family_scores"),text(4,"Constant"),bytes(5,familyAttr));
        byte[] graph=concat(bytes(1,attackNode),bytes(1,familyNode),text(2,"p4-fixed-fixture"),bytes(11,input("numeric_values",1,43)),bytes(11,input("numeric_missing",1,43)),bytes(11,input("categorical_codes",7,3)),bytes(12,input("attack_score",1,1)),bytes(12,input("family_scores",1,families.length)));
        return concat(integer(1,8),text(2,"p4-test-only"),bytes(7,graph),bytes(8,integer(2,17)));
    }
    private static byte[] floats(float... values){var b=ByteBuffer.allocate(values.length*4).order(ByteOrder.LITTLE_ENDIAN);for(float v:values)b.putFloat(v);return b.array();}
    private static byte[] input(String name,int type,int width){byte[] shape=concat(bytes(1,integer(1,1)),bytes(1,integer(1,width)));return concat(text(1,name),bytes(2,bytes(1,concat(integer(1,type),bytes(2,shape)))));}
    private static byte[] text(int field,String text){return bytes(field,text.getBytes(StandardCharsets.UTF_8));}
    private static byte[] integer(int field,long value){return concat(varint(field*8),varint(value));}
    private static byte[] bytes(int field,byte[] value){return concat(varint(field*8+2),varint(value.length),value);}
    private static byte[] varint(long v){var out=new ByteArrayOutputStream();while(v>127){out.write((int)(v&127)|128);v>>>=7;}out.write((int)v);return out.toByteArray();}
    private static byte[] concat(byte[]... items){var out=new ByteArrayOutputStream();for(var b:items)out.writeBytes(b);return out.toByteArray();}
}
