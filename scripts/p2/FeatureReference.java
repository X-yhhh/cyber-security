import java.nio.file.*;
import java.util.*;

/** JDK25 独立统计参考：直接按截止点筛选包并两遍求总体方差，不复用 Go 增量公式。
 * 只核对基础数值与因果边界；连接/水位/质量另由 Go 场景测试覆盖。 */
public class FeatureReference {
    record Packet(long seq, long at, boolean out, int length) {}
    static void near(String name, double actual, double expected) {
        if (Math.abs(actual - expected) > 1e-8 * Math.max(1, Math.abs(expected)))
            throw new AssertionError(name + ": " + actual + " != " + expected);
    }
    static double mean(double[] a) { return Arrays.stream(a).average().orElse(0); }
    static double std(double[] a) {
        double m = mean(a), sum = 0;
        for (double v : a) sum += (v - m) * (v - m);
        return Math.sqrt(sum / a.length);
    }
    public static void main(String[] args) throws Exception {
        if (Runtime.version().feature() != 25) throw new IllegalStateException("需要 JDK25");
        Path root = Path.of(args[0]);
        Map<String,List<Packet>> packets = new HashMap<>();
        for (String line : Files.readAllLines(root.resolve("packets.tsv")).subList(1, Files.readAllLines(root.resolve("packets.tsv")).size())) {
            String[] v = line.split("\t");
            packets.computeIfAbsent(v[0], k -> new ArrayList<>()).add(new Packet(Long.parseLong(v[1]),Long.parseLong(v[2]),Boolean.parseBoolean(v[3]),Integer.parseInt(v[4])));
        }
        int checked = 0;
        for (String line : Files.readAllLines(root.resolve("reference.tsv"))) {
            if (line.startsWith("scenario\t")) continue;
            String[] v = line.split("\t"); long first = Long.parseLong(v[1]), end = Long.parseLong(v[2]);
            List<Packet> ps = packets.get(v[0]).stream().filter(p -> p.at >= first && p.at <= end).sorted(Comparator.comparingLong(Packet::at).thenComparingLong(Packet::seq)).toList();
            long out = ps.stream().filter(Packet::out).count();
            double[] lengths = ps.stream().mapToDouble(Packet::length).toArray();
            near("last",ps.getLast().at,Long.parseLong(v[3]));
            near("packetsOut",out,Double.parseDouble(v[4])); near("packetsIn",ps.size()-out,Double.parseDouble(v[5]));
            near("bytesOut",ps.stream().filter(Packet::out).mapToLong(Packet::length).sum(),Double.parseDouble(v[6]));
            near("bytesIn",ps.stream().filter(p -> !p.out).mapToLong(Packet::length).sum(),Double.parseDouble(v[7]));
            near("min",Arrays.stream(lengths).min().orElseThrow(),Double.parseDouble(v[8]));
            near("max",Arrays.stream(lengths).max().orElseThrow(),Double.parseDouble(v[9]));
            near("mean",mean(lengths),Double.parseDouble(v[10])); near("std",std(lengths),Double.parseDouble(v[11]));
            if (ps.size()==1) {
                if (!v[12].equals("null") || !v[13].equals("null")) throw new AssertionError("单包 IAT 非 null");
            } else {
                double[] iat = new double[ps.size()-1];
                for (int i=1;i<ps.size();i++) iat[i-1]=ps.get(i).at-ps.get(i-1).at;
                near("iatMean",mean(iat),Double.parseDouble(v[12])); near("iatStd",std(iat),Double.parseDouble(v[13]));
            }
            checked++;
        }
        System.out.println("jdk="+Runtime.version()+" independent_reference_snapshots="+checked+" status=passed");
    }
}
