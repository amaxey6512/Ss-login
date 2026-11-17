#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

// Host calls this on the main thread with its visible view controller.
__attribute__((visibility("default")))
void SSLoginPresent(UIViewController *host, void (^completion)(BOOL)) {
    if (![NSThread isMainThread] || !host || !host.viewIfLoaded.window || host.presentedViewController) { if (completion) completion(NO); return; }
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"SS LOGIN" message:@"Enter your authorized username and password. Your device identifier will be sent for verification." preferredStyle:UIAlertControllerStyleAlert];
    alert.overrideUserInterfaceStyle = UIUserInterfaceStyleDark;
    alert.view.tintColor = [UIColor colorWithRed:0.70 green:0.96 blue:0.29 alpha:1];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *f) { f.placeholder = @"Username"; f.autocorrectionType = UITextAutocorrectionTypeNo; f.autocapitalizationType = UITextAutocapitalizationTypeNone; }];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *f) { f.placeholder = @"Password"; f.autocorrectionType = UITextAutocorrectionTypeNo; f.autocapitalizationType = UITextAutocapitalizationTypeNone; f.secureTextEntry = YES; }];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:^(__unused UIAlertAction *a) { if (completion) completion(NO); }]];
    __weak UIAlertController *weakAlert = alert;
    [alert addAction:[UIAlertAction actionWithTitle:@"Verify access" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *a) {
        NSString *username = [weakAlert.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSString *password = weakAlert.textFields.lastObject.text;
        NSString *hwid = UIDevice.currentDevice.identifierForVendor.UUIDString;
        if (!username.length || !password.length || !hwid.length) { if (completion) completion(NO); return; }
        NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://onestate-key-compass.lovable.app/api/public/check"]];
        request.HTTPMethod = @"POST"; request.timeoutInterval = 20;
        [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        request.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{@"username":username,@"password":password,@"hwid":hwid} options:0 error:NULL];
        NSURLSession *session = [NSURLSession sessionWithConfiguration:NSURLSessionConfiguration.ephemeralSessionConfiguration];
        [[session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            NSInteger status = [response isKindOfClass:NSHTTPURLResponse.class] ? [(NSHTTPURLResponse *)response statusCode] : 0;
            id json = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL] : nil;
            id valid = [json isKindOfClass:NSDictionary.class] ? json[@"valid"] : nil;
            BOOL ok = !error && status >= 200 && status < 300 && valid && CFGetTypeID((__bridge CFTypeRef)valid) == CFBooleanGetTypeID() && [valid boolValue];
            dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(ok); });
        }] resume];
        [session finishTasksAndInvalidate];
    }]];
    [host presentViewController:alert animated:YES completion:nil];
}
