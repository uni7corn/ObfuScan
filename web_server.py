#!/usr/bin/env python3
import os
import subprocess
import json
import tempfile
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
import cgi

# 定义服务器地址和端口
HOST = '127.0.0.1'
PORT = 8080

# ObfuScan可执行文件路径
OBFUSCAN_EXECUTABLE = os.path.join(os.path.dirname(__file__), 'ObfuScan.exe')

# LibChecker 规则库
# 动态获取当前 Python 脚本所在的目录，并拼接上 LibChecker-Rules 文件夹
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
LIBCHECKER_RULES_DIR = os.path.join(CURRENT_DIR, 'LibChecker-Rules')


class LibCheckerMatcher:
    """LibChecker 规则匹配器"""

    def __init__(self, rules_dir):
        self.rules_dir = rules_dir
        self.rules = []
        self.load_rules()

    def load_rules(self):
        native_dir = os.path.join(self.rules_dir, 'native-libs')
        if not os.path.exists(native_dir):
            print(f"[警告] LibChecker 规则目录未找到: {native_dir}")
            return

        count = 0
        for filename in os.listdir(native_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(native_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        raw_rule = json.load(f)

                        # 初始化一个扁平化的规则字典
                        parsed_rule = {
                            '_filename': filename[:-5],  # e.g. libImSDK.so
                            'name': raw_rule.get('name'),
                            'isRegex': raw_rule.get('isRegex', False),
                            'label': '',
                            'team': '',
                            'description': ''
                        }

                        # 深入解析 LibChecker 的嵌套多语言结构
                        if 'data' in raw_rule and isinstance(raw_rule['data'], list):
                            zh_data = None
                            en_data = None

                            # 遍历寻找中文和英文
                            for lang_item in raw_rule['data']:
                                locale = lang_item.get('locale', '')
                                if locale == 'zh-Hans':
                                    zh_data = lang_item.get('data', {})
                                elif locale == 'en':
                                    en_data = lang_item.get('data', {})

                            # 优先级：中文优先，没有就用英文，再没有就取第一个
                            target_data = zh_data or en_data or raw_rule['data'][0].get('data', {})

                            parsed_rule['label'] = target_data.get('label', '')
                            # 注意：LibChecker字段名叫 dev_team
                            parsed_rule['team'] = target_data.get('dev_team', '')
                            parsed_rule['description'] = target_data.get('description', '')

                        self.rules.append(parsed_rule)
                        count += 1
                except Exception as e:
                    print(f"[错误] 解析规则文件失败 {filename}: {e}")

        print(f"[成功] 加载了 {count} 条 LibChecker 原生库规则。")

    def match(self, so_path):
        """用规则匹配 SO 文件名"""
        if not self.rules:
            return None

        basename = os.path.basename(so_path)  # 例如从 lib/arm64-v8a/libImSDK.so 拿到 libImSDK.so

        for rule in self.rules:
            is_regex = rule['isRegex']
            rule_name = rule['name'] or rule['_filename']

            if is_regex:
                try:
                    if re.search(rule_name, basename):
                        return rule
                except re.error:
                    pass
            else:
                if basename == rule_name or basename == rule['_filename']:
                    return rule
        return None


# 全局初始化匹配器
MATCHER = LibCheckerMatcher(LIBCHECKER_RULES_DIR)


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(self.get_index_html().encode('utf-8'))
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == '/analyze':
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST',
                         'CONTENT_TYPE': self.headers['Content-Type']}
            )

            if 'apk' not in form or form['apk'].filename == '':
                self.send_error(400, 'No APK file uploaded')
                return

            apk_file = form['apk']
            lang = form.getvalue('lang', 'zh')

            with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as temp_file:
                temp_file.write(apk_file.file.read())
                temp_apk_path = temp_file.name

            try:
                result = self.run_obfuscan(temp_apk_path, lang)
                self.send_response(200)
                self.send_header('Content-type', 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(json.dumps(result, ensure_ascii=False).encode('utf-8'))
            finally:
                if os.path.exists(temp_apk_path):
                    os.unlink(temp_apk_path)
        else:
            self.send_error(404)

    def run_obfuscan(self, apk_path, lang='zh'):
        try:
            if not os.path.exists(OBFUSCAN_EXECUTABLE):
                return {'error': True, 'message': f'ObfuScan.exe不存在。请先构建项目。'}

            cmd = [OBFUSCAN_EXECUTABLE, apk_path]
            if lang == 'en':
                cmd.append('--en')

            result = subprocess.run(cmd,
                                    capture_output=True, text=True, encoding='utf-8'
                                    )

            if result.returncode != 0:
                return {'error': True, 'message': f'ObfuScan执行失败: {result.stderr}'}

            try:
                analysis_result = json.loads(result.stdout)

                if lang == 'zh':
                    if '结果' in analysis_result:
                        for item in analysis_result['结果']:
                            so_path = item.get('so文件', '')
                            if so_path:
                                match_rule = MATCHER.match(so_path)
                                if match_rule:
                                    item['LibChecker'] = {
                                        '名称': match_rule['label'] or match_rule['_filename'],
                                        '团队': match_rule['team'],
                                        '描述': match_rule['description']
                                    }
                else:
                    if 'results' in analysis_result:
                        for item in analysis_result['results']:
                            so_path = item.get('so_file', '')
                            if so_path:
                                match_rule = MATCHER.match(so_path)
                                if match_rule:
                                    item['libchecker'] = {
                                        'name': match_rule['label'] or match_rule['_filename'],
                                        'team': match_rule['team'],
                                        'description': match_rule['description']
                                    }

                return {'error': False, 'result': analysis_result}
            except json.JSONDecodeError as e:
                return {'error': True, 'message': f'解析JSON出错: {str(e)}'}
        except Exception as e:
            return {'error': True, 'message': f'发生异常: {str(e)}'}

    def get_index_html(self):
        return '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ObfuScan - APK分析工具</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; background-color: #f4f4f4; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: #35424a; color: #ffffff; padding: 20px; margin-bottom: 20px; border-radius: 5px; }
        h1 { font-size: 28px; margin-bottom: 10px; }
        .lang-switch { float: right; margin-top: -40px; }
        .lang-btn { background: rgba(255,255,255,0.2); color: white; padding: 6px 12px; border: 1px solid rgba(255,255,255,0.3); border-radius: 4px; cursor: pointer; font-size: 14px; margin-left: 5px; }
        .lang-btn:hover { background: rgba(255,255,255,0.3); }
        .lang-btn.active { background: rgba(255,255,255,0.3); }
        .upload-section, .results-section { background: #ffffff; padding: 20px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="file"] { padding: 10px; border: 1px solid #ddd; border-radius: 4px; width: 100%; }
        button { background: #35424a; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #2c3e50; }
        .loading { display: none; margin-top: 20px; padding: 10px; background: #f8f8f8; border: 1px solid #ddd; border-radius: 4px; }
        .results-section { display: none; }
        .summary { background: #f8f9fa; padding: 15px; margin-bottom: 20px; border-radius: 4px; }
        .summary-item { margin-bottom: 10px; }
        .result-item { margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 4px; }
        .result-item.high { border-left: 5px solid #dc3545; }
        .result-item.medium { border-left: 5px solid #ffc107; }
        .result-item.low { border-left: 5px solid #28a745; }
        .result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .so-name { font-weight: bold; font-size: 18px; }
        .risk-level { padding: 5px 10px; border-radius: 15px; font-size: 14px; font-weight: bold; }
        .risk-level.high { background: #dc3545; color: white; }
        .risk-level.medium { background: #ffc107; color: #333; }
        .risk-level.low { background: #28a745; color: white; }
        .result-details { margin-top: 10px; }
        .detail-item { margin-bottom: 8px; }
        .detail-label { font-weight: bold; margin-right: 10px; }
        .suspicious-points, .entry-previews, .vmp-info { margin-top: 10px; }
        .suspicious-points ul { margin-left: 20px; }
        .entry-preview { margin-bottom: 8px; padding: 8px; background: #f8f9fa; border-radius: 4px; }
        .vmp-info { padding: 10px; background: #e3f2fd; border-radius: 4px; }
        .error-message { background: #f8d7da; color: #721c24; padding: 15px; border: 1px solid #f5c6cb; border-radius: 4px; margin-top: 20px; }
        
        /* LibChecker 专属绿色样式 */
        .libchecker-info {
            margin-bottom: 15px;
            padding: 12px;
            background: #f0fdf4;
            border-left: 4px solid #22c55e;
            border-radius: 4px;
        }
        .libchecker-name { font-size: 16px; color: #166534; }
        .libchecker-team { color: #15803d; font-size: 14px; margin-left: 5px; }
        .libchecker-desc { margin-top: 6px; font-size: 13px; color: #4b5563; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1 id="title">ObfuScan - APK分析工具</h1>
            <p id="subtitle">快速分析Android APK中的Native SO文件，检测混淆、加壳等保护措施</p>
            <div class="lang-switch">
                <button id="langZh" class="lang-btn active" onclick="switchLang('zh')">中文</button>
                <button id="langEn" class="lang-btn" onclick="switchLang('en')">English</button>
            </div>
        </header>
        
        <div class="upload-section">
            <h2 id="uploadTitle">上传APK文件</h2>
            <form class="upload-form" id="uploadForm" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="apkFile" id="selectFileLabel">选择APK文件：</label>
                    <input type="file" id="apkFile" name="apk" accept=".apk">
                </div>
                <button type="submit" id="analyzeBtn">开始分析</button>
            </form>
            <div class="loading" id="loading">
                <p id="loadingText">正在分析并匹配组件指纹...请稍候</p>
            </div>
        </div>
        
        <div class="results-section" id="resultsSection">
            <h2 id="resultsTitle">分析结果</h2>
            <div class="summary" id="summary"></div>
            <div id="resultList"></div>
        </div>
    </div>
    
    <script>
        const lang = {
            zh: {
                title: 'ObfuScan - APK分析工具',
                subtitle: '快速分析Android APK中的Native SO文件，检测混淆、加壳等保护措施',
                uploadTitle: '上传APK文件',
                selectFileLabel: '选择APK文件：',
                analyzeBtn: '开始分析',
                loadingText: '正在分析并匹配组件指纹...请稍候',
                resultsTitle: '分析结果',
                summary: '汇总信息',
                totalSo: '总SO数量',
                highRisk: '高风险',
                mediumRisk: '中风险',
                lowRisk: '低风险',
                knownComponent: '💡 已知组件',
                detectionResult: '检测结果',
                description: '说明',
                suspiciousPoints: '可疑点',
                entryPreview: '入口预览',
                name: '名称',
                address: '地址',
                preview: '预览',
                vmpJudgment: 'VMP判断',
                vmpScore: 'VMP分数',
                vmpFeatures: 'VMP特征',
                suggestion: '建议',
                selectApk: '请选择APK文件',
                error: '异常',
                high: '高',
                medium: '中',
                low: '低'
            },
            en: {
                title: 'ObfuScan - APK Analyzer',
                subtitle: 'Quickly analyze Native SO files in Android APK, detect obfuscation and packing',
                uploadTitle: 'Upload APK File',
                selectFileLabel: 'Select APK File:',
                analyzeBtn: 'Start Analysis',
                loadingText: 'Analyzing and matching component fingerprints... Please wait',
                resultsTitle: 'Analysis Results',
                summary: 'Summary',
                totalSo: 'Total SO Count',
                highRisk: 'High Risk',
                mediumRisk: 'Medium Risk',
                lowRisk: 'Low Risk',
                knownComponent: '💡 Known Component',
                detectionResult: 'Detection Result',
                description: 'Description',
                suspiciousPoints: 'Suspicious Points',
                entryPreview: 'Entry Previews',
                name: 'Name',
                address: 'Address',
                preview: 'Preview',
                vmpJudgment: 'VMP Judgment',
                vmpScore: 'VMP Score',
                vmpFeatures: 'VMP Features',
                suggestion: 'Suggestion',
                selectApk: 'Please select an APK file',
                error: 'Error',
                high: 'High',
                medium: 'Medium',
                low: 'Low'
            }
        };
        
        let currentLang = 'zh';
        
   function switchLang(language) {
    currentLang = language;
    document.getElementById('langZh').classList.toggle('active', language === 'zh');
    document.getElementById('langEn').classList.toggle('active', language === 'en');

    const t = lang[language];
    document.getElementById('title').textContent = t.title;
    document.getElementById('subtitle').textContent = t.subtitle;
    document.getElementById('uploadTitle').textContent = t.uploadTitle;
    document.getElementById('selectFileLabel').textContent = t.selectFileLabel;
    document.getElementById('analyzeBtn').textContent = t.analyzeBtn;
    document.getElementById('loadingText').textContent = t.loadingText;
    document.getElementById('resultsTitle').textContent = t.resultsTitle;

    if (lastResult) {
        document.getElementById('summary').innerHTML =
            '<div class="error-message">' +
            (language === 'en'
                ? 'Language changed. Please run analysis again.'
                : '语言已切换，请重新分析。') +
            '</div>';
        document.getElementById('resultList').innerHTML = '';
        lastResult = null;
    }
}
        
        let lastResult = null;
        
        document.getElementById('uploadForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            formData.append('lang', currentLang);
            const apkFile = document.getElementById('apkFile').files[0];
            const t = lang[currentLang];
            
            if (!apkFile) { alert(t.selectApk); return; }
            
            document.getElementById('loading').style.display = 'block';
            document.getElementById('resultsSection').style.display = 'none';
            
            fetch('/analyze', { method: 'POST', body: formData })
            .then(res => res.json())
            .then(data => {
                document.getElementById('loading').style.display = 'none';
                if (data.error) {
                    document.getElementById('resultsSection').style.display = 'block';
                    document.getElementById('summary').innerHTML = '<div class="error-message">' + data.message + '</div>';
                    document.getElementById('resultList').innerHTML = '';
                } else {
                    lastResult = data.result;
                    displayResults(data.result);
                }
            })
            .catch(err => {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('resultsSection').style.display = 'block';
                document.getElementById('summary').innerHTML = '<div class="error-message">' + t.error + ': ' + err.message + '</div>';
                document.getElementById('resultList').innerHTML = '';
            });
        });
        
        function displayResults(result) {
            document.getElementById('resultsSection').style.display = 'block';
            const t = lang[currentLang];
            
            const summary = result['汇总'] || result['summary'];
            let summaryHtml = '<h3>' + t.summary + '</h3>';
            summaryHtml += '<div class="summary-item"><span class="detail-label">' + t.totalSo + ':</span> ' + (summary['总so数量'] || summary['total_so_count'] || 0) + '</div>';
            summaryHtml += '<div class="summary-item"><span class="detail-label">' + t.highRisk + ':</span> ' + (summary['高风险'] || summary['high_risk'] || 0) + '</div>';
            summaryHtml += '<div class="summary-item"><span class="detail-label">' + t.mediumRisk + ':</span> ' + (summary['中风险'] || summary['medium_risk'] || 0) + '</div>';
            summaryHtml += '<div class="summary-item"><span class="detail-label">' + t.lowRisk + ':</span> ' + (summary['低风险'] || summary['low_risk'] || 0) + '</div>';
            document.getElementById('summary').innerHTML = summaryHtml;
            
            const results = result['结果'] || result['results'];
            let resultsHtml = '';
            
            results.forEach(item => {
                const riskLevel = item['风险等级'] || item['risk_level'];
                let riskClass = riskLevel === '高' || riskLevel === 'High' ? 'high' : (riskLevel === '中' || riskLevel === 'Medium' ? 'medium' : 'low');
                let displayRisk = riskLevel === '高' ? t.high : (riskLevel === '中' ? t.medium : (riskLevel === '低' ? t.low : riskLevel));
                
                resultsHtml += '<div class="result-item ' + riskClass + '">';
                resultsHtml += '<div class="result-header">';
                resultsHtml += '<span class="so-name">' + (item['so文件'] || item['so_file']) + '</span>';
                resultsHtml += '<span class="risk-level ' + riskClass + '">' + displayRisk + '</span>';
                resultsHtml += '</div>';
                resultsHtml += '<div class="result-details">';
                
                if (item['LibChecker'] || item['libchecker']) {
                    const lc = item['LibChecker'] || item['libchecker'];
                    resultsHtml += '<div class="libchecker-info">';
                    resultsHtml += '<span class="detail-label">' + t.knownComponent + ':</span> ';
                    resultsHtml += '<strong class="libchecker-name">' + (lc['名称'] || lc['name'] || '') + '</strong>';
                    if (lc['团队'] || lc['team']) {
                        resultsHtml += '<span class="libchecker-team">(' + (lc['团队'] || lc['team']) + ')</span>';
                    }
                    if (lc['描述'] || lc['description']) {
                        resultsHtml += '<div class="libchecker-desc">' + (lc['描述'] || lc['description']) + '</div>';
                    }
                    resultsHtml += '</div>';
                }
                
                resultsHtml += '<div class="detail-item"><span class="detail-label">' + t.detectionResult + ':</span> ' + (item['检测结果'] || item['detection_result'] || '') + '</div>';
                resultsHtml += '<div class="detail-item"><span class="detail-label">' + t.description + ':</span> ' + (item['说明'] || item['description'] || '') + '</div>';
                
                const suspiciousPoints = item['可疑点'] || item['suspicious_points'] || [];
                if (suspiciousPoints.length > 0) {
                    resultsHtml += '<div class="suspicious-points"><span class="detail-label">' + t.suspiciousPoints + ':</span><ul>';
                    suspiciousPoints.forEach(point => { resultsHtml += '<li>' + point + '</li>'; });
                    resultsHtml += '</ul></div>';
                }
                
                const entryPreviews = item['入口预览'] || item['entry_previews'] || [];
                if (entryPreviews.length > 0) {
                    resultsHtml += '<div class="entry-previews"><span class="detail-label">' + t.entryPreview + ':</span>';
                    entryPreviews.forEach(entry => {
                        resultsHtml += '<div class="entry-preview"><strong>' + (entry['名称'] || entry['name']) + '</strong> (' + t.address + ': ' + (entry['地址'] || entry['address']) + ')<br>' + t.preview + ': ' + (entry['预览'] || entry['preview']) + '</div>';
                    });
                    resultsHtml += '</div>';
                }
                
                if (item['VMP判断'] || item['vmp_judgment']) {
                    resultsHtml += '<div class="vmp-info"><span class="detail-label">' + t.vmpJudgment + ':</span> ' + (item['VMP判断'] || item['vmp_judgment']) + '<br><span class="detail-label">' + t.vmpScore + ':</span> ' + (item['VMP分数'] || item['vmp_score']) + '<br>';
                    const vmpFeatures = item['VMP特征'] || item['vmp_features'] || [];
                    if (vmpFeatures.length > 0) {
                        resultsHtml += '<span class="detail-label">' + t.vmpFeatures + ':</span><ul>';
                        vmpFeatures.forEach(f => { resultsHtml += '<li>' + f + '</li>'; });
                        resultsHtml += '</ul>';
                    }
                    resultsHtml += '</div>';
                }
                
                resultsHtml += '<div class="detail-item" style="margin-top:10px;"><span class="detail-label">' + t.suggestion + ':</span> ' + (item['建议'] || item['suggestion'] || '') + '</div>';
                resultsHtml += '</div></div>';
            });
            document.getElementById('resultList').innerHTML = resultsHtml;
        }
    </script>
</body>
</html>
'''


def run_server():
    server = HTTPServer((HOST, PORT), RequestHandler)
    print(f"\n[OK] 服务器运行在 http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    run_server()
