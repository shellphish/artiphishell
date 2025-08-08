import java.io.File;

import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

public class FileFromRestOfPath {
    public void doPathTraversal(StaplerRequest req, StaplerResponse rsp) throws Exception {
        File f = new File("rootDir", "persona" + req.getRestOfPath());
        rsp.serveFile(req,f.toURI().toURL());
    }

    public String doNotCare(StaplerRequest req) {
        return new String(req.getRestOfPath());
    }
}
