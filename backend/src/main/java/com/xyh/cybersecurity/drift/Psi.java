package com.xyh.cybersecurity.drift;

/**
 * 群体稳定性指数（PSI）：{@code Σ (a_i − e_i) · ln(a_i / e_i)}，e 为基线占比，a 为运行时占比。
 *
 * <p>空箱按 {@code epsilon} 截底（两侧同样处理），避免除零与 ln(0)；截底后不再重新归一化，与训练端约定一致。
 * 阈值口径沿用 M8：&gt; 0.2 为 warning，&gt; 0.3 为 alert。</p>
 */
public final class Psi {
    private Psi() { }

    /**
     * @param expected 基线各箱占比（和为 1）
     * @param actual   运行时各箱计数，长度与 expected 相同
     * @return PSI；运行时有效样本为 0 时返回 null（无法判定，不当作“无漂移”）
     */
    public static Double of(double[] expected, long[] actual, double epsilon) {
        if (expected.length != actual.length) throw new IllegalArgumentException("PSI_BINS_MISMATCH");
        long total = 0;
        for (long count : actual) total += count;
        if (total == 0) return null;
        double psi = 0;
        for (int i = 0; i < expected.length; i++) {
            double e = Math.max(expected[i], epsilon);
            double a = Math.max(actual[i] / (double) total, epsilon);
            psi += (a - e) * Math.log(a / e);
        }
        return psi;
    }
}
