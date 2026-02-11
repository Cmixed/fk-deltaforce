use std::collections::{HashMap, BTreeMap};
use std::fs;
use std::path::PathBuf;
use console::Term;

#[derive(Debug, Default)]
struct AceScanStats {
    total_attempts: usize,
    blocked_attempts: usize,
    unique_files: HashMap<String, usize>,
    processes: HashMap<String, usize>,
    rules_triggered: HashMap<String, usize>,
    file_extensions: HashMap<String, usize>,
    target_categories: HashMap<String, usize>,
    time_distribution: BTreeMap<String, usize>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 获取命令行参数
    let args: Vec<String> = std::env::args().collect();
    
    // 确定日志文件路径：有参数用参数，否则用默认的 fk-df.txt
    let log_path = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from("fk-df.txt")
    };
    
    // 检查文件是否存在
    if !log_path.exists() {
        return Err(format!(
            "❌ 文件不存在: {}\n   使用方法: {} <文件路径> 或直接拖放文件到程序上",
            log_path.display(),
            args.get(0).map(|s| s.as_str()).unwrap_or("程序名")
        ).into());
    }
    
    // 验证是否为有效的火绒日志文件
    if !is_huorong_log(&log_path)? {
        return Err(format!(
            "❌ 不是有效的火绒安全日志文件（需包含 'SGuard' 和 '操作文件：' 特征）: {}",
            log_path.display()
        ).into());
    }
    
    println!("🔍 正在分析日志文件: {}", log_path.display());
    let contents = fs::read_to_string(&log_path)?;
    let stats = parse_ace_logs_precise(&contents);
    
    if stats.total_attempts == 0 {
        return Err(format!("❌ 未检测到有效的 ACE 扫盘日志条目（文件: {}）", log_path.display()).into());
    }
    
    generate_detailed_report(&stats);
    export_high_risk_targets(&stats)?;
    
    println!("\n>>> 按任意键退出程序 <<<");
    Term::stdout().read_char().unwrap();
    Ok(())
}

/// 检测是否为火绒安全日志（快速特征检测）
fn is_huorong_log(path: &PathBuf) -> Result<bool, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(path)?;
    let has_sguard = contents.contains("SGuard64") || contents.contains("SGuardSvc64");
    let has_file_op = contents.contains("操作文件：");
    Ok(has_sguard && has_file_op && contents.contains("触犯自定义防护规则"))
}

fn parse_ace_logs_precise(logs: &str) -> AceScanStats {
    let mut stats = AceScanStats::default();
    let entries: Vec<&str> = logs
        .split(&">".repeat(60))
        .filter(|e| !e.trim().is_empty() && e.contains("SGuard") && e.contains("操作文件："))
        .collect();

    for entry in entries {
        stats.total_attempts += 1;

        if let Some(file_path) = extract_field(entry, "操作文件：", &["操作结果：", "操作类型：", "\r\n", "\n"]) {
            let file_path = file_path.trim().to_string();
            if !file_path.is_empty() {
                *stats.unique_files.entry(file_path.clone()).or_insert(0) += 1;

                let ext = file_path
                    .rsplit('.')
                    .next()
                    .map(|s| s.to_lowercase())
                    .unwrap_or_else(|| "无扩展名".to_string());
                *stats.file_extensions.entry(ext).or_insert(0) += 1;

                categorize_target(&file_path, &mut stats.target_categories);
            }
        }

        if let Some(proc_path) = extract_field(entry, "操作进程：", &["操作进程命令行：", "操作类型：", "\r\n", "\n"]) {
            let proc_name = proc_path
                .split('\\')
                .last()
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            *stats.processes.entry(proc_name).or_insert(0) += 1;
        }

        if let Some(rule_name) = extract_field(entry, "触犯规则：", &["操作类型：", "\r\n", "\n"]) {
            let rule = rule_name.trim().to_string();
            if !rule.is_empty() {
                *stats.rules_triggered.entry(rule).or_insert(0) += 1;
            }
        }

        if entry.contains("操作结果：已阻止") {
            stats.blocked_attempts += 1;
        }

        if let Some(hour) = extract_hour(entry) {
            let hour_key = format!("{:02}:00-{:02}:59", hour, hour);
            *stats.time_distribution.entry(hour_key).or_insert(0) += 1;
        }
    }

    stats
}

fn extract_field<'a>(text: &'a str, prefix: &str, terminators: &[&str]) -> Option<&'a str> {
    text.find(prefix).and_then(|start| {
        let value_start = start + prefix.len();
        if value_start >= text.len() {
            return None;
        }
        
        let value_end = terminators
            .iter()
            .filter_map(|term| text[value_start..].find(term))
            .min()
            .map(|pos| value_start + pos)
            .unwrap_or(text.len());
        
        if value_start >= value_end {
            None
        } else {
            Some(&text[value_start..value_end])
        }
    })
}

fn extract_hour(entry: &str) -> Option<u32> {
    entry
        .lines()
        .next()
        .and_then(|first_line| {
            first_line
                .split_whitespace()
                .nth(1)
                .and_then(|time_part| time_part.split(':').next())
                .and_then(|hour_str| hour_str.parse::<u32>().ok())
        })
        .filter(|&h| h < 24)
}

fn categorize_target(file_path: &str, categories: &mut HashMap<String, usize>) {
    let lower_path = file_path.to_lowercase();

    let category = if lower_path.contains("system32\\drivers") || lower_path.contains("syswow64\\drivers") {
        "系统驱动"
    } else if lower_path.contains("system32") {
        "System32核心"
    } else if lower_path.contains("syswow64") {
        "SysWOW64(32位)"
    } else if lower_path.contains("microsoft.net") || lower_path.contains("dotnet") {
        ".NET组件"
    } else if lower_path.contains("anti cheat expert") 
        || lower_path.contains("sguard") 
        || lower_path.contains("ace") 
        || lower_path.contains("eac") {
        "反作弊组件"
    } else if lower_path.contains("windows\\systemapps") || lower_path.contains("windowsapps") {
        "WindowsApps"
    } else if lower_path.contains("programdata") || lower_path.contains("appdata") {
        "用户数据目录"
    } else if lower_path.contains("windows\\winsxs") {
        "WinSxS组件存储"
    } else {
        "其他系统文件"
    };

    *categories.entry(category.to_string()).or_insert(0) += 1;
}

/// 计算字符串在等宽终端中的显示宽度（中文字符占2，英文占1）
fn display_width(s: &str) -> usize {
    s.chars().map(|c| {
        if c.len_utf8() > 1 {
            2 // 中文、emoji等宽字符
        } else {
            1 // ASCII字符
        }
    }).sum()
}

/// 截断或填充字符串到指定显示宽度
fn pad_to_width(s: &str, width: usize) -> String {
    let current_width = display_width(s);
    if current_width >= width {
        // 需要截断
        let mut result = String::new();
        let mut current = 0;
        for c in s.chars() {
            let w = if c.len_utf8() > 1 { 2 } else { 1 };
            if current + w > width - 1 {
                result.push('…');
                break;
            }
            result.push(c);
            current += w;
        }
        result
    } else {
        // 填充空格
        format!("{}{}", s, " ".repeat(width - current_width))
    }
}

fn generate_detailed_report(stats: &AceScanStats) {
    const WIDTH: usize = 76;
    println!("\n{}", "=".repeat(WIDTH));
    println!("{:^WIDTH$}", "🛡️ ACE反作弊系统扫盘行为深度分析报告");
    println!("{:^WIDTH$}", format!("(基于 {} 条有效日志条目)", stats.total_attempts));
    println!("{}", "=".repeat(WIDTH));

    println!("\n「📊 核心指标」");
    println!("  • 总扫盘尝试次数: {:>10}", stats.total_attempts);
    let block_rate = if stats.total_attempts > 0 {
        stats.blocked_attempts as f64 / stats.total_attempts as f64 * 100.0
    } else {
        0.0
    };
    println!("  • 成功阻止次数:   {:>10} (拦截率: {:.1}%)", stats.blocked_attempts, block_rate);
    println!("  • 唯一目标文件数: {:>10}", stats.unique_files.len());
    println!("  • 活跃进程数:     {:>10}", stats.processes.len());

    println!("\n「🔍 进程行为分析」");
    let mut procs: Vec<_> = stats.processes.iter().collect();
    procs.sort_by(|a, b| b.1.cmp(a.1));
    for (i, (proc, count)) in procs.iter().take(5).enumerate() {
        let risk_level: &str = if **count > 500 {
            "🔴 高危"
        } else if **count > 200 {
            "🟠 中危"
        } else {
            "🟢 低危"
        };
        println!("  {:2}. {:28} {:>8} 次  {}", i + 1, proc, count, risk_level);
    }

    // 修复对齐：统一使用固定宽度
    println!("\n「⚠️ 高频扫描目标 (Top 15)」");
    println!("  {:>4}  {:<50} {:>8}  {}", "排名", "文件路径", "频次", "风险");
    println!("  {}", "-".repeat(74));

    let mut files: Vec<_> = stats.unique_files.iter().collect();
    files.sort_by(|a, b| b.1.cmp(a.1));

    for (i, (file, count)) in files.iter().take(15).enumerate() {
        let risk: &str = if **count > 30 {
            "🔴"
        } else if **count > 10 {
            "🟠"
        } else {
            "🟢"
        };
        
        // 处理文件路径显示：截断中间部分
        let display_path = if display_width(file) > 50 {
            let total_chars = file.chars().count();
            let prefix_len = 20;
            let suffix_len = 26;
            let prefix: String = file.chars().take(prefix_len).collect();
            let suffix: String = file.chars().skip(total_chars.saturating_sub(suffix_len)).collect();
            format!("{}...{}", prefix, suffix)
        } else {
            file.to_string()
        };
        
        // 使用 pad_to_width 确保严格对齐
        let padded_path = pad_to_width(&display_path, 50);
        println!("  {:>3}. {} {:>8}  {}", i + 1, padded_path, count, risk);
    }

    // 修复格式对齐：使用 display_width 计算中文字符宽度进行补偿
    println!("\n「📁 扫描目标分类统计」");
    println!("  {:<20} {:>12} {:>12}  {}", "分类", "扫描次数", "占比", "风险");
    println!("  {}", "-".repeat(74));
    
    let mut cats: Vec<_> = stats.target_categories.iter().collect();
    cats.sort_by(|a, b| b.1.cmp(a.1));
    
    for (cat, count) in &cats {
        let count_val = **count;
        let percent = count_val as f64 / stats.total_attempts as f64 * 100.0;
        let risk_icon: &str = if count_val > 1000 {
            "🔴"
        } else if count_val > 300 {
            "🟠"
        } else {
            "🟢"
        };
        
        // 计算需要填充的空格数，确保对齐
        let cat_width = display_width(cat);
        let target_width = 20usize;
        let padding = if cat_width < target_width {
            target_width - cat_width
        } else {
            0
        };
        
        println!(
            "  {}{:padding$} {:>10} 次 ({:>6.1}%)  {}",
            cat, "", count_val, percent, risk_icon
        );
    }

    println!("\n「🧩 文件类型分布」");
    let mut exts: Vec<_> = stats.file_extensions.iter().collect();
    exts.sort_by(|a, b| b.1.cmp(a.1));
    for (ext, count) in exts.iter().take(8) {
        let count_val = **count;
        let percent = count_val as f64 / stats.total_attempts as f64 * 100.0;
        println!("  .{:6} {:>8} 次 ({:>6.1}%)", ext, count_val, percent);
    }

    if !stats.time_distribution.is_empty() {
        println!("\n「⏰ 扫描行为时间分布」");
        let mut times: Vec<_> = stats.time_distribution.iter().collect();
        times.sort_by_key(|(k, _)| *k);

        let peak_count = times.iter().map(|(_, v)| **v).max().unwrap_or(1);
        let peak_time = times.iter().max_by_key(|(_, v)| **v).map(|(t, _)| t.as_str()).unwrap_or("");
        println!("  扫描高峰: {} (共 {} 次)", peak_time, peak_count);

        for (time, count) in times.iter().take(12) {
            let count_val = **count;
            let bar_width = (count_val as f64 / peak_count as f64 * 40.0).round() as usize;
            let bar = "█".repeat(bar_width);
            println!("  {} {:>6} {}", time, count_val, bar);
        }
    }

    println!("\n「🛡️ 安全加固建议」");
    println!("  1️⃣  驱动层防护：存储驱动(storqosflt.sys/storvsp.sys)被高频扫描，");
    println!("      建议对 System32\\drivers 目录设置「仅监控」而非「阻止」");
    println!("  2️⃣  虚拟化检测：hvhostsvc.dll/vmms.exe 等组件被扫描，");
    println!("      可能用于检测虚拟机环境，评估是否需放行相关路径");
    println!("  3️⃣  规则优化：100%拦截率可能导致游戏启动异常，");
    println!("      建议对反作弊组件自身目录设置「放行」，对驱动目录设置「询问」");

    println!("\n{}", "=".repeat(WIDTH));
}

fn export_high_risk_targets(stats: &AceScanStats) -> Result<(), Box<dyn std::error::Error>> {
    let mut files: Vec<_> = stats.unique_files.iter().collect();
    files.sort_by(|a, b| b.1.cmp(a.1));

    let mut csv = String::from("排名,扫描频次,文件路径,风险等级,文件类型,完整路径\n");

    for (i, (file, count)) in files.iter().enumerate().take(200) {
        let count_val = **count;
        let risk: &str = if count_val > 30 {
            "高危"
        } else if count_val > 10 {
            "中危"
        } else {
            "低危"
        };
        let ext = file
            .rsplit('.')
            .next()
            .unwrap_or("无")
            .to_string();

        let safe_file = if file.contains(',') || file.contains('\n') || file.contains('\"') {
            format!("\"{}\"", file.replace('\"', "\"\""))
        } else {
            file.to_string()
        };
        
        // 添加完整路径列（方便直接复制到火绒规则）
        csv.push_str(&format!("{},{},{},{},{},\"{}\"\n", i + 1, count_val, safe_file, risk, ext, file));
    }

    // 添加UTF-8 BOM解决Excel乱码
    let mut bom_csv = Vec::from(&[0xEFu8, 0xBB, 0xBF][..]);
    bom_csv.extend_from_slice(csv.as_bytes());
    
    fs::write("high_risk_targets.csv", bom_csv)?;
    
    println!("\n✅ 已导出高频扫描目标清单: high_risk_targets.csv");
    println!("   (UTF-8 BOM 格式，Excel/WPS 可直接正常打开中文)");

    Ok(())
}