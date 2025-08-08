import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;

import hudson.security.AccessControlled;
import hudson.security.Permission;
import hudson.util.ListBoxModel;

import java.net.URL;

public class WebMethodMissingPostAnnotation {
    public void doCheckWhatever(@AncestorInPath AccessControlled ac, @QueryParameter String value) throws Exception {
        ac.checkPermission(Permission.CREATE);
        new URL(value).openConnection();
    }
    public ListBoxModel doFillWhatever() {
        ListBoxModel box = new ListBoxModel();
        box.add("whatever");
        return box;
    }
}
