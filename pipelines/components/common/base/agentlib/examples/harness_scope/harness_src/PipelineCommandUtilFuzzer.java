import jenkins.model.Jenkins;
import aixcc.util.StaplerReplacer;
import java.nio.ByteBuffer;
import java.util.*;

import io.jenkins.plugins.UtilPlug.UtilMain;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.kohsuke.stapler.WebApp;
import org.kohsuke.stapler.RequestImpl;
import org.kohsuke.stapler.ResponseImpl;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.mockito.Mockito;
import static org.mockito.Mockito.*;

public class PipelineCommandUtilFuzzer {
    public static void fuzzerTestOneInput(byte[] data) throws Exception {
        if (data.length < 5) return;
        String whole = new String(data);

        String[] parts = whole.split("\0");
        if (parts.length == 3) {
            UtilMain nw = new UtilMain();
            Jenkins mockJ = Mockito.mock(Jenkins.class);
            when(mockJ.hasPermission(Jenkins.ADMINISTER)).thenReturn(false);
            nw.jenkin = mockJ;
            try {
                StaplerReplacer replacer = new StaplerReplacer();
                ;
                replacer.setWebApp(new WebApp(Mockito.mock(ServletContext.class)));

                HttpServletRequest mockRequest = Mockito.mock(HttpServletRequest.class);
                List<String> headerNamesList = new ArrayList<>();

                headerNamesList.add(parts[0]);

                Enumeration<String> headerNamesEnumeration = Collections.enumeration(headerNamesList);
                when(mockRequest.getHeaderNames()).thenReturn(headerNamesEnumeration);
                when(mockRequest.getHeader(parts[0])).thenReturn(parts[1]);
                when(mockRequest.getHeader("Referer")).thenReturn("http://localhost:8080/UtilPlug/execCommandUtils");

                RequestImpl req = new RequestImpl(replacer.stapler, mockRequest, Collections.emptyList(), null);
                replacer.setCurrentRequest(req);

                // Response
                HttpServletResponse mockResp = Mockito.mock(HttpServletResponse.class);
                ResponseImpl resp = new ResponseImpl(replacer.stapler, mockResp);
                replacer.setCurrentResponse(resp);


                nw.doexecCommandUtils(parts[2], req, resp);
            }
            catch(Exception e) {
            }
        }
        else {
        }
    }
}
