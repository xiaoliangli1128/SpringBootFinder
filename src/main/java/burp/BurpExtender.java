package burp;


import com.google.common.hash.Hashing;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

public class BurpExtender implements IBurpExtender, IScannerCheck {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    // test / grep strings
    private static final byte[] GREP_STRING_SPRING_BOOT = "Whitelabel Error Page".getBytes();
    private List<IParameter> parameters;
    IResponseInfo oresponse, response;
    String ores, oResBodyInfo;
    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {


        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("SpringBootFinder");
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("+++++ load success! ^_^ ");
        stdout.println("+++++ Author: Pyth0n");
        stdout.println("+++++ Description: find website ico or 404 page is springboot ");
        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);

    }

    // helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    private List<int[]> getMatches(byte[] response, byte[] match) {
        List<int[]> matches = new ArrayList<int[]>();
        callbacks.printOutput(helpers.bytesToString(response));
        int start = 0;
        while (start < response.length) {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[]{start, start + match.length});
            start += match.length;
        }

        return matches;
    }

    // 判断响应包的图标是不是spring 如果是就报告这个IScanIssue
    private IScanIssue isSpringBoot(IHttpRequestResponse newRequestResponse) {

        byte[] res = newRequestResponse.getResponse();
        oresponse = helpers.analyzeResponse(res);
        /*当返回包为200的时候 且存在Accept-Ranges: bytes或者Content-Type: image/x-icon favicon才大概率可能存在，再去看hash值*/
        if (oresponse.getStatusCode() == 200 && (oresponse.getHeaders().contains("Accept-Ranges: bytes")
                || oresponse.getHeaders().contains("Content-Type: image/x-icon"))) {
            //IHttpRequestResponse 返回的byte[] response
            ores = new String(res);
            oResBodyInfo = ores.substring(oresponse.getBodyOffset());
            byte[] destResponse;
            destResponse = Arrays.copyOfRange(res, oresponse.getBodyOffset(), res.length);
            String base64Str = Base64.getMimeEncoder().encodeToString(destResponse);
            int favicon = Hashing.murmur3_32().hashString(base64Str.replace("\r", "") + "\n", StandardCharsets.UTF_8).asInt();
            if (116323821 == favicon) {
                return (new CustomScanIssue(
                        newRequestResponse.getHttpService(),
                        helpers.analyzeRequest(newRequestResponse).getUrl(),
                        new IHttpRequestResponse[]{callbacks.applyMarkers(newRequestResponse, null, null)},
                        "SpringBoot framework favicon found",
                        "The website favicon  is  springboot \n you can check SpringBoot Vuln: " + helpers.analyzeRequest(newRequestResponse).getUrl(),
                        "High",
                        "Firm"));

            }

        } else
            return null;


        return null;

    }

    //根据path 递归遍历加入favicon图标
    private List<String> getUniquePathList(IHttpRequestResponse baseRequestResponse) {
        URL oldURL = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
        String path = helpers.analyzeRequest(baseRequestResponse).getUrl().getPath();
        String[] pathList = path.split("/");
        if (pathList.length > 1) {
            List<String> uniquePath = Arrays.stream(pathList).distinct().collect(Collectors.toList());
            ArrayList<Integer> indexInt = new ArrayList<>();
            for (int i = 0; i < uniquePath.size(); i++) {
                int index = 0;
                while ((index = path.indexOf(uniquePath.get(i), index)) > 0) {
                    indexInt.add(index);
                    index += uniquePath.get(i).length();
                }

            }
            List<String> urlPath = new ArrayList();
            ;
            for (Integer i : indexInt) {
                urlPath.add(oldURL.getProtocol() + "://" + oldURL.getAuthority() + path.substring(0, i) + "favicon.ico");
            }
            return urlPath;
        } else return null;

    }

    private List<IHttpRequestResponse> uniqueResponse(IHttpRequestResponse baseRequestResponse, List<String> urlPath) {
        /*获取URL*/
        List<IHttpRequestResponse> newHttpRequest = new ArrayList<>();

        for (String url : urlPath) {
            byte[] NewReq = new byte[0];
            try {
                NewReq = helpers.buildHttpRequest(new URL(url));
            } catch (MalformedURLException e) {
                e.printStackTrace();
            }
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), NewReq);
            //IResponseInfo oresponse可以获取body的getBodyOffset()
            newHttpRequest.add(checkRequestResponse);
        }
        return newHttpRequest;
    }


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        // look for matches of our passive check grep string
        List<IScanIssue> issues = new ArrayList<>(1);

        List<String> urlPath = getUniquePathList(baseRequestResponse);
        List<IHttpRequestResponse> uniqueResponse = uniqueResponse(baseRequestResponse, urlPath);
        for (IHttpRequestResponse newRequestResponse : uniqueResponse) {
            issues.add(isSpringBoot(newRequestResponse));
        }

        int statusCode=helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode();
       // if (statusCode == 404 || statusCode==403) { // 是404的页面再去匹配 页面是否有指纹
            List<int[]> matches = getMatches(baseRequestResponse.getResponse(), GREP_STRING_SPRING_BOOT);
            if (matches.size() > 0) {
                // report the issue
                issues.add(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, matches)},
                        "SpringBoot Error Page found",
                        "The response contains the string: " + helpers.bytesToString(GREP_STRING_SPRING_BOOT),
                        "High",
                        "Firm"));

            }
       // }

        return issues;

    }


    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        // This method is called when multiple issues are reported for the same URL
        // path by the same extension-provided check. The value we return from this
        // method determines how/whether Burp consolidates the multiple issues
        // to prevent duplication
        //
        // Since the issue name is sufficient to identify our issues as different,
        // if both issues have the same name, only report the existing issue
        // otherwise report both issues

        if ( existingIssue.getUrl().getHost().equals(newIssue.getUrl().getHost())||existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return -1;
        } else return 0;
    }


}

//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue {
    private final IHttpService httpService;
    private final URL url;
    private final IHttpRequestResponse[] httpMessages;
    private final String name;
    private final String detail;
    private final String severity;
    private final String confidence;


    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity,
            String confidence) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.confidence = confidence;

    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return String.format("  SpringBoot is a new open source lightweight framework developed by the Pivotal team since 2013 " +
                "and released in its first version in April 2014. It is based on Spring 4.0 and not only inherits " +
                "the best features of the Spring framework, but also simplifies the whole process of building " +
                "and developing Spring applications by simplifying configuration. In addition SpringBoot " +
                "through the integration of a large number of frameworks makes the dependency package version " +
                "conflict and reference instability and other issues are well resolved. try Access <ul><li>/env</li>" +
                "<li>/actuator</li><ul>");
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

}