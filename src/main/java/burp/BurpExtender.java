package burp;


import com.google.common.hash.Hashing;

import java.io.PrintWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    // test / grep strings
    private static final byte[] GREP_STRING_SPRING_BOOT = "Whitelabel Error Page".getBytes();
    private List<IParameter> parameters;
    IResponseInfo oresponse, response;
    String ores, NewReq, oResBodyInfo;
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
        stdout.println("Author: Pyth0n");
        stdout.println("Description: find website ico or 404 page is springboot ");
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

    // 判断响应包的图标是不是spring
    public boolean isSpringBoot(byte[] destResponse) {
        String base64Str = Base64.getMimeEncoder().encodeToString(destResponse);
        int favicon = Hashing.murmur3_32().hashString(base64Str.replace("\r", "") + "\n", StandardCharsets.UTF_8).asInt();
        if (116323821 == favicon) {
            return true;
        } else return false;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        // look for matches of our passive check grep string
        List<IScanIssue> issues = new ArrayList<>(1);
        /*获取URL*/
        String OldReq = helpers.bytesToString(baseRequestResponse.getRequest());
        String Rurl = helpers.analyzeRequest(baseRequestResponse).getUrl().getPath();
        stdout.println("Rul"+Rurl);
        String[] strlist = Rurl.split("/");
        if (strlist.length < 1) {
            return null;
        }
        for (int i = strlist.length - 1; i > 0; i--) { // 反转 path 从后
            if (!"".equals(strlist[i])) {
                NewReq = OldReq.replace(strlist[i], "favicon.ico?");
                IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), helpers.stringToBytes(NewReq));
                //IResponseInfo oresponse可以获取body的getBodyOffset()
                byte[] res = checkRequestResponse.getResponse();
                oresponse = helpers.analyzeResponse(res);
                if (oresponse.getStatusCode() == 200) { //当200的时候说明 favicon存在，再去看hash值
                    //IHttpRequestResponse 返回的byte[] response
                    ores = new String(res);
                    oResBodyInfo = ores.substring(oresponse.getBodyOffset());
                    byte[] destResponse;
                    destResponse = Arrays.copyOfRange(res, oresponse.getBodyOffset(), res.length);
                    if (destResponse != null) {
                        if (isSpringBoot(destResponse)) {
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, null)},
                                    "SpringBoot framework favicon found",
                                    "The website favicon  is  springboot \n you can check SpringBoot Vuln",
                                    "High",
                                    "Firm"));
                            return issues;
                        }
                    }

                }

            }


        }
        if (helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() == 404) { // 是404的页面再去匹配 页面是否有指纹
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
                return issues;
            } else return null;
        }

        return null;
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
        System.out.println(existingIssue.getUrl().getHost() + "<---->" + newIssue.getUrl().getHost());
        if (existingIssue.getUrl().getHost().equals(newIssue.getUrl().getHost()) || existingIssue.getIssueName().equals
                (newIssue.getIssueName())) {
            return -1;
        } else return 0;
    }


}

//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;


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