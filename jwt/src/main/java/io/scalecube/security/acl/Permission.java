package io.scalecube.security.acl;


/**
 *  An approval of a mode of access to a resource.
 *  @see io.scalecube.security.auth.AccessControl#tryAccess(String, String)
 */
public class Permission {

  public static class Builder {
    String subject;
    String action;

    Builder subject(String subject) {
      this.subject = subject;
      return this;
    }

    Builder action(String action) {
      this.action = action;
      return this;
    }

    public Permission build() {
      return new Permission(this);
    }
  }

  private final String subject;
  private final String action;

  private Permission(Permission.Builder builder) {
    this.subject = builder.subject;
    this.action = builder.action;
  }

  public String action() {
    return this.action;
  }

  public String subject() {
    return this.subject;
  }

  /* (non-Javadoc)
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return new StringBuilder()
        .append("Permission [subject=")
        .append(this.subject)
        .append(", action=")
        .append(this.action)
        .append("]")
        .toString();
  }

  public static Builder builder() {
    return new Builder();
  }
}
