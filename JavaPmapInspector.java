import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.LongSummaryStatistics;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.util.stream.Collectors.groupingBy;

public class JavaPmapInspector {
    private static final Pattern WHITE_SPACE_SEPARATOR = Pattern.compile("\\s+");
    private static Config config;

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage:");
            System.err.println("   pmap -X pid > pmap.txt; java JavaPmapInspector.java pmap.txt");
            System.err.println("   java JavaPmapInspector.java <(pmap -X pid)");
            System.err.println("   pmap -X pid | java JavaPmapInspector.java -");
            System.err.println();
            System.err.println("Inspect `pmap -X` output of a java process, requires Java11.");
            System.err.println();
            System.err.println("WARNING: May not be 100% accurate as most memory mappings are anonymous, which ");
            System.err.println("means that segment patterns with the same protections may be _bagged _ together.");
            System.exit(1);
        }
        config = new Config();

        List<String> lines = read(args);

        System.out.printf("cmd: %s%n", lines.get(0));
        var globalStat = GlobalStat.of(lines.get(lines.size() - 1));


        var msi = new MemorySegmentIdentifier();
        var memorySegments = lines.stream().skip(2)
                                  .takeWhile(line -> !line.matches("\\s+====.*"))
                                  .collect(Collector.of(
                                          ArrayDeque<MemorySegment>::new,
                                          (a, line) -> {
                                              var memorySegmemt = MemorySegment.from(line);

                                              if (a.isEmpty()) {
                                                  a.add(memorySegmemt);
//                                                  System.out.println("==> 1st  = " + memorySegmemt);
                                              } else {
                                                  SegmentIdentifierResult mergeResult = msi.tryMergeMapping(a.peekLast(), memorySegmemt);
                                                  if (mergeResult != SegmentIdentifierResult.CONTIGUOUS_MAPPING) {
                                                      a.add(memorySegmemt);
                                                  }
//                                                  System.out.printf("==> %s = %s as %s%n", mergeResult, memorySegmemt, a.peekLast().type);
                                              }
                                          },
                                          (a, b) -> {
                                              throw new UnsupportedOperationException();
                                          }
                                  ));

        memorySegments.stream().filter(m -> m.type == SegmentType.UNKNOWN).forEach(System.out::println);

        // Print report
        System.out.printf("%nShared file mappings:%n");
        var sharedMappings = memorySegments.stream()
                                           .filter(m -> m.type == SegmentType.SHARED_MAPPED_FILE)
                                           .collect(groupingBy(
                                                   m -> m.mapping,
                                                   LinkedHashMap::new,
                                                   multiCollectorOf(List.of(
                                                           Collectors.counting(),
                                                           Collectors.summarizingLong(m1 -> m1.size_kib),
                                                           Collectors.summarizingLong(m1 -> m1.rss_kib)
                                                   ))
                                           ));
        sharedMappings.forEach((key, value) -> System.out.printf("%18s count=%-5s rssMin=%-10s rssMax=%-10s%n",
                                                                 key,
                                                                 value.get(0),
                                                                 ((LongSummaryStatistics) value.get(1)).getMin(),
                                                                 ((LongSummaryStatistics) value.get(1)).getMax()
        ));

        var result = memorySegments.stream().collect(groupingBy(
                m -> m.type,
                LinkedHashMap::new,
                multiCollectorOf(List.of(
                        Collectors.counting(),
                        Collectors.summingLong(m1 -> m1.size_kib),
                        Collectors.summingLong(m1 -> m1.rss_kib)
                        // TODO rss stats (avg, etc.) ?
                ))
        ));

        System.out.printf("%nMemory mappings:%n");
        result.forEach((key, value) -> System.out.printf("%18s count=%-5s reserved=%-10s rss=%-10s%n",
                                                         key,
                                                         value.get(0),
                                                         value.get(1),
                                                         value.get(2)));
        System.out.printf("%n");
        System.out.printf("stats: %s%n", globalStat);
    }


    private static class Config {
        private final long java_heap_max_start_address = Long.parseUnsignedLong("7f1000000000", 16);

        private long page_size_kib = 4;
        private int yellow_pages = 2;
        private int red_pages = 1;
        private int reserved_pages = 1;
        private long thread_guard_pages_kib = (yellow_pages + red_pages + reserved_pages) * page_size_kib; // By default 2 Yellow + 1 Red + 1 Reserved * page size
        // https://code.woboq.org/userspace/glibc/nptl/allocatestack.c.html#550
        private long thread_size_kib = thread_guard_pages_kib + 1008 + page_size_kib; // glibc adds one page to the allocated stack size, if the size is multiple of 64K. This is to avoid aliasing problem.

        private final int glibc_guard_page_kib = 4;

        private long non_java_thread_size_kib = 1028 + glibc_guard_page_kib; // TODO why 1028 and not 1024 ? aliasing counter measure ?

        private long malloc_arena_size_kib = 64 * 1024;

    }


    private static class MemorySegment {


        private final String[] fields;
        private final long startAddress;
        private final long inode;
        private long size_kib;
        private long rss_kib;
        private String mapping = "";

        private SegmentType type = SegmentType.UNKNOWN;
        private final String permissions;

        public MemorySegment(String line) {
            fields = WHITE_SPACE_SEPARATOR.split(line.trim());
            startAddress = Long.parseUnsignedLong(fields[0], 16);
            permissions = fields[1];
            size_kib = Long.parseLong(fields[5]);
            rss_kib = Long.parseLong(fields[6]);
            inode = Long.parseLong(fields[4]);
            if (fields.length == 19) {
                mapping = fields[18];
            }
        }

        public static MemorySegment from(String line) {
            return new MemorySegment(line);
        }


        @Override
        public String toString() {
            return String.format("type=%18s startAddress=%-16s perm=%s size=%-10d rss=%-10s mapping=%s",
                                 type,
                                 Long.toHexString(startAddress),
                                 permissions,
                                 size_kib,
                                 rss_kib,
                                 mapping);
        }
    }

    private static class MemorySegmentIdentifier {
        SegmentIdentifierResult tryMergeMapping(MemorySegment lowerAddressBlock,
                                                MemorySegment higherAddressBlock) {

            // Identifies Linux kernel specific mappings
            // https://stackoverflow.com/questions/19938324/what-are-vdso-and-vsyscall
            // https://lwn.net/Articles/615809/
            if (higherAddressBlock.mapping != null) {
                if (Set.of("[vsyscall]", "[vdso]", "[vvar]").contains(higherAddressBlock.mapping)) {
                    higherAddressBlock.type = SegmentType.KERNEL_MAPPING;
                    return SegmentIdentifierResult.SINGLE_SEGMENT_MAPPING;
                }
                if (Objects.equals("[heap]", higherAddressBlock.mapping)) {
                    higherAddressBlock.type = SegmentType.MAIN_NATIVE_HEAP;
                    return SegmentIdentifierResult.SINGLE_SEGMENT_MAPPING;
                }
                if (Objects.equals("[stack]", higherAddressBlock.mapping)) {
                    higherAddressBlock.type = SegmentType.MAIN_NATIVE_STACK;
                    return SegmentIdentifierResult.SINGLE_SEGMENT_MAPPING;
                }
            }


            // https://github.com/corretto/corretto-11/blob/3b31d243a19774bebde63df21cc84e994a89439a/src/src/hotspot/os/linux/os_linux.cpp#L6048-L6085

            // Java thread pattern
            //     7f66b834a000 ---p 00000000  00:00       0       16       0       0          0         0        0              0              0               0    0       0      0           0
            //     7f66b834e000 rw-p 00000000  00:00       0     1012      92      92         92        92        0              0              0               0    0       0      0           0
            if (lowerAddressBlock.permissions.equals("---p")
                && lowerAddressBlock.size_kib == config.thread_guard_pages_kib
                && higherAddressBlock.permissions.equals("rw-p")
                && (lowerAddressBlock.size_kib + higherAddressBlock.size_kib) == config.thread_size_kib
                && lowerAddressBlock.type == SegmentType.UNKNOWN) { // segment not already identified

                lowerAddressBlock.type = SegmentType.JAVA_THREAD;
                lowerAddressBlock.size_kib += higherAddressBlock.size_kib;
                lowerAddressBlock.rss_kib += higherAddressBlock.rss_kib;

                return SegmentIdentifierResult.CONTIGUOUS_MAPPING;
            }

            // Non java thread
            //     7f69eb8f6000 ---p 00000000  00:00       0        4       0       0          0         0        0              0              0               0    0       0      0           0
            //     7f69eb8f7000 rw-p 00000000  00:00       0     1028      12      12         12        12        0              0              0               0    0       0      0           0
            if (lowerAddressBlock.permissions.equals("---p")
                && lowerAddressBlock.size_kib == config.glibc_guard_page_kib
                && higherAddressBlock.permissions.equals("rw-p")
                && (lowerAddressBlock.size_kib + higherAddressBlock.size_kib) == config.non_java_thread_size_kib) {

                lowerAddressBlock.type = SegmentType.NON_JAVA_THREAD;
                lowerAddressBlock.size_kib += higherAddressBlock.size_kib;
                lowerAddressBlock.rss_kib += higherAddressBlock.rss_kib;

                return SegmentIdentifierResult.CONTIGUOUS_MAPPING;
            }


            // Malloc Arena thread pattern, only recognize blocks of 64MiB
            //     7f672c000000 rw-p 00000000  00:00       0     9568    9452    9452       9452      9452        0              0              0               0    0       0      0           0
            //     7f672c958000 ---p 00000000  00:00       0    55968       0       0          0         0        0              0              0               0    0       0      0           0
            if (lowerAddressBlock.permissions.equals("rw-p")
                && higherAddressBlock.permissions.equals("---p")
                && (lowerAddressBlock.size_kib + higherAddressBlock.size_kib) / config.malloc_arena_size_kib == 1
                && lowerAddressBlock.type == SegmentType.UNKNOWN) { // segment not already identified

                lowerAddressBlock.type = SegmentType.MALLOC_ARENA;
                lowerAddressBlock.size_kib += higherAddressBlock.size_kib;
                lowerAddressBlock.rss_kib += higherAddressBlock.rss_kib;

                return SegmentIdentifierResult.CONTIGUOUS_MAPPING;
            }

            // Mapped file
            //     7f6b17490000 r-xp 00000000  08:01 3531531    17672   14912   14912      14912         0        0              0              0               0    0       0      0           0 libjvm.so
            //     7f6b185d2000 ---p 01142000  08:01 3531531     2044       0       0          0         0        0              0              0               0    0       0      0           0 libjvm.so
            //     7f6b187d1000 r--p 01141000  08:01 3531531      764     764     764        764       764        0              0              0               0    0       0      0           0 libjvm.so
            //     7f6b18890000 rw-p 01200000  08:01 3531531      232     232     232        232       208        0              0              0               0    0       0      0           0 libjvm.so
            if (lowerAddressBlock.inode > 0) {
                lowerAddressBlock.type = SegmentType.MAPPED_FILE;
                if (lowerAddressBlock.permissions.matches("[r-][w-]-s")) {
                    lowerAddressBlock.type = SegmentType.SHARED_MAPPED_FILE;
                }
                if (lowerAddressBlock.inode == higherAddressBlock.inode) {
                    lowerAddressBlock.size_kib += higherAddressBlock.size_kib;
                    lowerAddressBlock.rss_kib += higherAddressBlock.rss_kib;

                    return SegmentIdentifierResult.CONTIGUOUS_MAPPING;
                }
                return SegmentIdentifierResult.FIRST_OF_CONTIGUOUS_SEGMENT_MAPPING;
            }


            // Java Heap
            //        740000000 rw-p 00000000  00:00       0  3164800 2746068 2746068    2746068   2746068        0              0              0               0    0       0      0           0
            //        8012a0000 ---p 00000000  00:00       0  1029504       0       0          0         0        0              0              0               0    0       0      0           0
            // 3gb heap (740000000 -> 800000000) + 1260000 (19267584 bytes, 18816 kib) of compressed class space ?
//            if (startAddress < config.java_heap_max_start_address) {
//                type = SegmentType.JAVA_HEAP;
//            }

            if (lowerAddressBlock.startAddress < config.java_heap_max_start_address
                && lowerAddressBlock.permissions.equals("rw-p")
                && higherAddressBlock.permissions.equals("---p")
                && lowerAddressBlock.type == SegmentType.UNKNOWN) {
                lowerAddressBlock.type = SegmentType.JAVA_HEAP;
                lowerAddressBlock.size_kib += higherAddressBlock.size_kib;
                lowerAddressBlock.rss_kib += higherAddressBlock.rss_kib;

                return SegmentIdentifierResult.CONTIGUOUS_MAPPING;
            }


            // Code Heap
            //     7f297490d000 rwxp 00000000  00:00       0     2496    1016    1016       1016      1016        0              0              0               0    0       0      0           0
            //     7f2974b7d000 ---p 00000000  00:00       0     3196       0       0          0         0        0              0              0               0    0       0      0           0
            //     7f2974e9c000 rwxp 00000000  00:00       0    63616   63588   63588      63588     63588        0              0              0               0    0       0      0           0
            //     7f2978cbc000 ---p 00000000  00:00       0    56416       0       0          0         0        0              0              0               0    0       0      0           0
            //     7f297c3d4000 rwxp 00000000  00:00       0    49344   49320   49320      49320     49320        0              0              0               0    0       0      0           0
            //     7f297f404000 ---p 00000000  00:00       0    70692       0       0          0         0        0              0              0               0    0       0      0           0
            if (lowerAddressBlock.permissions.equals("rwxp")
                && higherAddressBlock.permissions.equals("---p")) {
                lowerAddressBlock.type = SegmentType.CODE_HEAP;
                lowerAddressBlock.size_kib += higherAddressBlock.size_kib;
                lowerAddressBlock.rss_kib += higherAddressBlock.rss_kib;

                return SegmentIdentifierResult.CONTIGUOUS_MAPPING;
            }


            // Unknown pattern 16 + 3060
            //     7f66c4989000 ---p 00000000  00:00       0       16       0       0          0         0        0              0              0               0    0       0      0           0
            //     7f66c498d000 rw-p 00000000  00:00       0     3060    2140    2140       2140      2140        0              0              0               0    0       0      0           0
            if (lowerAddressBlock.permissions.equals("---p")
                && higherAddressBlock.permissions.equals("rw-p")
                && (lowerAddressBlock.size_kib + higherAddressBlock.size_kib) == 16 + 3060) {

                lowerAddressBlock.type = SegmentType.UNKNOWN_SEGMENT1;
                lowerAddressBlock.size_kib += higherAddressBlock.size_kib;
                lowerAddressBlock.rss_kib += higherAddressBlock.rss_kib;

                return SegmentIdentifierResult.CONTIGUOUS_MAPPING;
            }

            // Unkownn segment
            //     7f66c4c8a000 rw-p 00000000  00:00       0     2048    2048    2048       2048      2048        0              0              0               0    0       0      0           0
            if (lowerAddressBlock.size_kib == 2048) {
                lowerAddressBlock.type = SegmentType.UNKNOWN_SEGMENT2;
                return SegmentIdentifierResult.SINGLE_SEGMENT_MAPPING;
            }

            // other unknown possibilites
            // * Direct ByteBuffers
            // * Memory allocated by Unsafe.allocateMemory
            // * Unclosed resources (e.g. ZipInputStream)
            // * other native libraries
            return SegmentIdentifierResult.UNKNOWN_SINGLE_SEGMENT_MAPPING;
        }

    }

    private enum SegmentIdentifierResult {
        SINGLE_SEGMENT_MAPPING,
        UNKNOWN_SINGLE_SEGMENT_MAPPING,
        CONTIGUOUS_MAPPING,
        FIRST_OF_CONTIGUOUS_SEGMENT_MAPPING,
    }

    private enum SegmentType {
        UNKNOWN,
        MALLOC_ARENA,
        MAPPED_FILE,
        KERNEL_MAPPING,
        MAIN_NATIVE_HEAP,
        MAIN_NATIVE_STACK,
        NON_JAVA_THREAD,
        JAVA_HEAP,
        JAVA_THREAD,
        UNKNOWN_SEGMENT1,
        UNKNOWN_SEGMENT2,
        CODE_HEAP, SHARED_MAPPED_FILE,
    }


    private static List<String> read(String[] args) throws IOException {
        if (Objects.equals(args[0], "-")) {
            try (var br = new BufferedReader(new InputStreamReader(System.in))) {
                var lines = new ArrayList<String>(128);
                for (; ; ) {
                    String line = br.readLine();
                    if (line == null)
                        break;
                    lines.add(line);
                }
                return lines;
            }
        }

        Path pmap = Paths.get(args[0]);
        if (!Files.isReadable(pmap)) {
            System.err.printf("File '%s' does not exists or is not readable ", args[0]);
            System.exit(1);
        }
        return Files.readAllLines(pmap);
    }


    @SuppressWarnings("unchecked")
    private static <T> Collector<T, List<Object>, List<Object>> multiCollectorOf(List<Collector<T, ?, ?>> collectors) {
        return Collector.of(
                () -> collectors.stream().map(Collector::supplier)
                                .map(Supplier::get).collect(Collectors.toList()),
                (list, e) -> IntStream.range(0, collectors.size()).forEach(
                        i -> ((BiConsumer<Object, T>) collectors.get(i).accumulator()).accept(list.get(i), e)),
                (l1, l2) -> {
                    IntStream.range(0, collectors.size()).forEach(
                            i -> l1.set(i, ((BinaryOperator<Object>) collectors.get(i).combiner()).apply(l1.get(i), l2.get(i))));
                    return l1;
                },
                list -> {
                    IntStream.range(0, collectors.size()).forEach(
                            i -> list.set(i, ((Function<Object, Object>) collectors.get(i).finisher()).apply(list.get(i))));
                    return list;
                });
    }

    private static class GlobalStat {

        private String vsz_kib;
        private String rss_kib;

        public GlobalStat(String line) {
            var fields = WHITE_SPACE_SEPARATOR.split(line.trim());
            this.vsz_kib = fields[0];
            this.rss_kib = fields[1];

            // Ignores PSS (proportional share size), as the process memory is not shared with other process in the container
            // Example: process with 100k private pages, 500k pages shared with one other process, and 500k shared with four other processes
            // PSS = 100k + (500k / 2) + (500k / 5) = 450k

            // Ignoring Referenced. It indicates the amount of memory currently marked as referenced or accessed
            // Usually, for this use case looking at the RSS is enough.
        }

        public static GlobalStat of(String line) {
            return new GlobalStat(line);
        }

        @Override
        public String toString() {
            return String.format("vsz=%s kib %n rss=%s kib", vsz_kib, rss_kib);
        }
    }
}

