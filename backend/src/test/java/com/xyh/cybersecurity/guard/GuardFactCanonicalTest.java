package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import org.junit.jupiter.api.Test;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;

/** 窄事实编码必须与原 JCS 逐字节等价；特殊值和失败边界由原实现决定。 */
class GuardFactCanonicalTest {
    static final long MAX_SAFE=9_007_199_254_740_991L;

    private void sameAsCanonical(JsonNode value){
        var before=value==null?null:value.deepCopy();String original=value==null?null:value.toString();
        String expected;
        try{expected=canonical(value);}catch(ApiRequestException failure){
            assertThatThrownBy(()->canonicalFact(value)).isInstanceOf(ApiRequestException.class).hasMessage(failure.getMessage());
            assertThat(value).isEqualTo(before);assertThat(value==null?null:value.toString()).isEqualTo(original);return;
        }
        String actual=canonicalFact(value);
        assertThat(actual.getBytes(StandardCharsets.UTF_8)).containsExactly(expected.getBytes(StandardCharsets.UTF_8));
        assertThat(sha(actual.getBytes(StandardCharsets.UTF_8))).isEqualTo(sha(expected.getBytes(StandardCharsets.UTF_8)));
        assertThat(value).isEqualTo(before);
        assertThat(value==null?null:value.toString()).isEqualTo(original);
    }

    @Test void sortedAsciiFactsPreserveArrayOrderAndAllPrimitiveBoundaries(){
        var values=JSON.createArrayNode().addNull().add(false).add(true).add(0).add(-1).add(Integer.MIN_VALUE).add(Integer.MAX_VALUE)
                .add(-MAX_SAFE).add(MAX_SAFE).add(" !#$%&'()*+,-./:;<=>?@[]^_`{|}~");
        values.add(ShortNode.valueOf(Short.MIN_VALUE));values.add(BigIntegerNode.valueOf(BigInteger.valueOf(MAX_SAFE)));
        var fact=JSON.createObjectNode();fact.set("z",values);fact.set("A",JSON.createObjectNode());fact.set("",JSON.createArrayNode());
        sameAsCanonical(fact);
        assertThat(canonicalFact(object("z",1,"a",true,"A",null,"",List.of(2,1))))
                .isEqualTo("{\"\":[2,1],\"A\":null,\"a\":true,\"z\":1}");
        for(JsonNode value:values)sameAsCanonical(value);
    }

    @Test void floatingPointAndLargeIntegersUseOriginalRfc8785Representation(){
        var rfc=parse("{\"numbers\":[333333333.33333329,1E30,4.50,2e-3,1e-27,-0.0]}");
        sameAsCanonical(rfc);
        assertThat(canonicalFact(rfc)).isEqualTo("{\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27,0]}");
        for(JsonNode value:List.of(
                LongNode.valueOf(MAX_SAFE+1),LongNode.valueOf(-MAX_SAFE-1),LongNode.valueOf(Long.MIN_VALUE),LongNode.valueOf(Long.MAX_VALUE),
                BigIntegerNode.valueOf(new BigInteger("9007199254740993")),BigIntegerNode.valueOf(BigInteger.ONE.shiftLeft(100)),
                DecimalNode.valueOf(new BigDecimal("9007199254740993.1")),DecimalNode.valueOf(new BigDecimal("0.000000000000000000000000001")),
                FloatNode.valueOf(.5f),DoubleNode.valueOf(-0.0),DoubleNode.valueOf(Double.MIN_VALUE),DoubleNode.valueOf(Double.MAX_VALUE),
                DoubleNode.valueOf(Double.NaN),DoubleNode.valueOf(Double.POSITIVE_INFINITY)))sameAsCanonical(JSON.createArrayNode().add(value));
        assertThat(canonicalFact(JSON.createArrayNode().add(BigIntegerNode.valueOf(new BigInteger("9007199254740993")))))
                .isEqualTo("[9007199254740992]");
    }

    @Test void unicodeEscapesControlCharactersAndUnsafeKeysFallBackAsAWhole(){
        var unsafe=new ArrayList<String>(List.of("\"","\\","中文","é","\u2028","\u2029","😀","\u007f"));
        for(int c=0;c<0x20;c++)unsafe.add(String.valueOf((char)c));
        for(String text:unsafe){
            sameAsCanonical(object("a",List.of("already-appended",123),"z",text));
            var key=JSON.createObjectNode();key.put("safe",1);key.put(text,2);sameAsCanonical(key);
        }
        var utf16Order=JSON.createObjectNode();
        for(String key:List.of("\u20ac","\r","\ufb33","1","😀","\u0080","ö"))utf16Order.put(key,key);
        sameAsCanonical(utf16Order);
    }

    @Test void specialNodesAndSubclassesKeepJacksonSerializationSemantics(){
        sameAsCanonical(null);sameAsCanonical(JSON.createArrayNode().add(MissingNode.getInstance()));
        sameAsCanonical(JSON.createArrayNode().add(BinaryNode.valueOf(new byte[]{0,1,(byte)255})));
        sameAsCanonical(new POJONode(Map.of("z",1,"a",List.of(true,"text"))));
        // 该子类的 textValue 与真实序列化值不同，必须整值交回原序列化路径。
        var special=new TextNode("serialized"){@Override public String textValue(){return "not-serialized";}};
        var array=JSON.createArrayNode().add(special);
        sameAsCanonical(array);assertThat(canonicalFact(array)).isEqualTo("[\"serialized\"]");
        var nested=JSON.createObjectNode();nested.put("a",1);nested.set("z",special);sameAsCanonical(nested);
    }

    @Test void malformedUnicodeAndScalarRootsRetainOriginalOutcomes(){
        for(String text:List.of("\ud800","\udc00","prefix\ud800suffix")){
            sameAsCanonical(JSON.createArrayNode().add(text));
        }
        for(JsonNode scalar:List.of(NullNode.instance,BooleanNode.TRUE,IntNode.valueOf(1),TextNode.valueOf("text"))){
            assertThatThrownBy(()->canonical(scalar)).hasMessageContaining("INVALID_JSON_NUMBER_OR_UNICODE");
            sameAsCanonical(scalar);
        }
    }

    @Test void seededNestedFactsMatchBytesAndHashWithoutMutatingInput(){
        var random=new Random(0x4b3250524f4f46L);
        for(int i=0;i<400;i++)sameAsCanonical(JSON.createArrayNode().add(randomFact(random,5)));
        JsonNode deep=LongNode.valueOf(1);
        for(int i=0;i<160;i++)deep=JSON.createArrayNode().add(deep);
        sameAsCanonical(deep);
    }
    private JsonNode randomFact(Random random,int depth){
        int kind=random.nextInt(depth==0?5:7);
        return switch(kind){
            case 0->NullNode.instance;
            case 1->BooleanNode.valueOf(random.nextBoolean());
            case 2->IntNode.valueOf(random.nextInt());
            case 3->LongNode.valueOf(random.nextLong(-MAX_SAFE,MAX_SAFE+1));
            case 4->TextNode.valueOf(randomText(random));
            case 5->{var array=JSON.createArrayNode();for(int i=0,n=random.nextInt(5);i<n;i++)array.add(randomFact(random,depth-1));yield array;}
            default->{var object=JSON.createObjectNode();for(int i=0,n=random.nextInt(5);i<n;i++)object.set("key-"+i+randomText(random),randomFact(random,depth-1));yield object;}
        };
    }
    private String randomText(Random random){
        var text=new StringBuilder();
        for(int i=0,n=random.nextInt(33);i<n;i++){
            char c;do{c=(char)random.nextInt(0x20,0x7f);}while(c=='"'||c=='\\');text.append(c);
        }
        return text.toString();
    }
}
