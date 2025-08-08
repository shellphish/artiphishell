import java

import java

/**
 * A method that overrides an abstract method.
 */
class ConcreteImplementation extends Method {
  ConcreteImplementation() {
    // The method is not abstract
    not this.isAbstract() and
    // But it overrides an abstract method
    exists(Method abstractMethod |
      this.overrides(abstractMethod) and
      abstractMethod.isAbstract()
    )
  }
  
  /**
   * Get the abstract method that this method implements.
   */
  Method getAbstractMethod() {
    this.overrides(result) and
    result.isAbstract()
  }
}

from ConcreteImplementation impl, Method abstractMethod
where abstractMethod = impl.getAbstractMethod()
select 
        abstractMethod.getQualifiedName() as source_qualified_name,
        abstractMethod.getLocation() as source_location,
        impl.getQualifiedName() as target_qualified_name,
        impl.getLocation() as target_location
