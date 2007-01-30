# $Id: Passphrase.pm,v 1.18 2007/01/30 20:09:03 ajk Exp $

use strict;
use warnings;

package Data::Passphrase; {
    use Object::InsideOut qw(Exporter);

    use Readonly;

    Readonly my  $DEFAULT_RULES_FILE => '/etc/passphrase_rules';
    Readonly my  $RULE_ERROR_CODE    => 550;

    # evaluate to passphrase text in string context
    sub as_string :Stringify { $_[0]->get_passphrase() }

    # evaluate to passphrase length in numeric context
    sub as_number :Numerify {
        my ($self) = @_;
        my $passphrase = $self->get_passphrase();
        return defined $passphrase ? length $passphrase : 0;
    }

    use version; our $VERSION = qv('0.0.5');

    use Data::Passphrase::Ruleset;
    use Carp;
    use Fatal qw(open close);
    use HTTP::Status;

    # export procedural subroutine
    BEGIN {
        our @EXPORT_OK = qw(validate_passphrase);
    }

    # object attributes
    my @code       :Field(Std => 'code',                        );
    my @custom     :Field(Std => 'custom',    Type => 'Hash_ref');
    my @debug      :Field(Std => 'debug',     Type => 'Numeric' );
    my @message    :Field(Std => 'message'                      );
    my @passphrase :Field(Std => 'passphrase'                   );
    my @ruleset    :Field(Std => 'ruleset',                     );
    my @username   :Field(Std => 'username'                     );

    my %init_args :InitArgs = (
        code       => {            Field => \@code,       Type  => 'Numeric' },
        custom     => {            Field => \@custom,     Type  => 'Hash_ref'},
        debug      => {Def   => 0, Field => \@debug,      Type  => 'Numeric' },
        message    => {            Field => \@message,                       },
        passphrase => {            Field => \@passphrase,                    },
        ruleset    => {            Field => \@ruleset,                       },
        username   => {            Field => \@username,                      },
    );

    sub new {
        my ($class, $arg_ref) = @_;

        # unpack arguments
        my $debug = $arg_ref->{debug};

        $debug and warn 'initializing ', __PACKAGE__, ' object';

        # select a default rules file
        my $rules_file;
        if (!exists $arg_ref->{ruleset}) {
            $debug and warn 'autoconstructing ruleset with default file';
            $rules_file = $DEFAULT_RULES_FILE;
        }

        # allow
        elsif (!ref $arg_ref->{ruleset}) {
            $rules_file = $arg_ref->{ruleset};
        }

        # autoconstruct ruleset object
        if ($rules_file) {
            $arg_ref->{ruleset} = Data::Passphrase::Ruleset->new({
                debug => $debug,
                file  => $rules_file,
            });
        }

        # construct object
        my $self = $class->Object::InsideOut::new($arg_ref);

        return $self;
    }

    # access a hash with custom user data for use in rules
    sub get_data {
        my ($self, $name) = @_;
        my $custom_data = $self->get_custom();
        return defined $name ? $custom_data->{$name} : $custom_data;
    }

    # set custom data values
    sub set_data {
        my ($self, $name, $value) = @_;
        my $custom_data = $self->get_custom();
        $custom_data->{$name} = $value;
        $self->set_custom($custom_data);
    }

    # check the passphrase against rules
    sub validate {
        my ($self) = @_;

        # unpack attributes
        my $debug      = $self->get_debug     ();
        my $passphrase = $self->get_passphrase();

        # reset code & message
        $self->set_code   (undef);
        $self->set_message(undef);

        # iterate through rules
        my @rules = @{$self->get_ruleset()->get_rules()};
        $debug and warn 'invoking ', scalar @rules, ' rules';
        foreach my $rule (@rules) {

            # unpack rule attributes
            my $code     = $rule->get_code    ();
            my $disabled = $rule->get_disabled();
            my $message  = $rule->get_message ();
            my $validate = $rule->get_validate();

            # skip test-only rules
            next if !defined $validate || $disabled;

            $debug and warn 'invoking rule: ',
                       defined $message ? $message : '[message not available]';

            # call the subroutine of the next rule, passing data hash
            my $status = eval { $validate->($self, $self->get_data()) };

            # catch errors
            if ($@) {
                carp $@;
                $self->set_code   ($RULE_ERROR_CODE);
                $self->set_message('rule error'    );
                return;
            }

            # return on failure
            if (!$status) {

                # let the validate method set these if it wants to
                $self->set_message($message) if !defined $self->get_message();
                $self->set_code   ($code   ) if !defined $self->get_code   ();

                return;
            }

            # a return code of -1 means short-circuit
            last if $status == -1;
        }

        # set the code and message for success
        $self->set_code(RC_OK);
        $self->set_message('acceptable');

        return;
    }

=begin WSDL

_IN     request  $Data::Passphrase::Request  request parameters
_RETURN          $Data::Passphrase::Response response parameters
_DOC                                                   validate a passphrase

=end WSDL

=cut

    # procedural interface: given a passphrase and an optional
    # username, validate the passphrase
    sub validate_passphrase {
        my ($class, $arg_ref) = @_;

        # accept class as first argument for use with SOAP::Lite
        if (!defined $arg_ref) {
            $arg_ref = $class;
            $class = __PACKAGE__;
        }

        # unpack arguments
        my $debug = $arg_ref->{debug};

        $debug and warn 'validating supplied passphrase';
        my $passphrase_object = $class->new($arg_ref);

        $debug and warn 'calling validate()';
        $passphrase_object->validate();

        return {
            code    => $passphrase_object->get_code   (),
            message => $passphrase_object->get_message(),
        };
    }
}

1;
__END__

=head1 NAME

Data::Passphrase - passphrase strength checker

=head1 VERSION

This documentation refers to Data::Passphrase version 0.0.5.

=head1 SYNOPSIS

Object-oriented interface:

    use Data::Passphrase;
    
    # build passphrase object
    my $passphrase_object = Data::Passphrase->new({
        username => $ENV{LOGNAME},
    });
    
    # evaluate each rule in turn
    for (;;) {
        print 'Passphrase (clear): ';
        chomp (my $passphrase = <STDIN>);
    
        $passphrase_object->set_passphrase($passphrase);
        $passphrase_object->validate();
    
        my $code    = $passphrase_object->get_code   ();
        my $message = $passphrase_object->get_message();
        print "$code $message\n";
    }

Procedural interface:

    use Data::Passphrase qw(validate_passphrase);
    
    for (;;) {
        print 'Passphrase (clear): ';
        chomp (my $passphrase = <STDIN>);
    
        my $result = validate_passphrase {
            passphrase => $passphrase,
            username   => $ENV{LOGNAME},
        };
    
        print "$result->{code} $result->{message}\n";
    }

=head1 DESCRIPTION

This module provides object-oriented and procedural interfaces for
checking passphrase strength against a set of customizable rules.  An
Apache handler that provides HTTP and SOAP services makes
strength-checking possible by remote applications.

=head1 OBJECT-ORIENTED INTERFACE

This module provides an object class for each request, containing the
username, the passphrase submitted, configuration data, and more.
There is a constructor C<new>, which takes a reference to a hash of
initial attribute settings, and accessor methods of the form
get_I<attribute>() and set_I<attribute>().  See L</Attributes>.

The object class overloads string and numeric conversion for
convenience when writing rules.  In string context, an object
evaluates to the text of the passphrase itself.  In numeric context,
the object evaluates to the length of the passphrase.

=head2 Methods

In addition to the constructor and accessor methods, the following
special methods are available.

=head3 get_data()

    $value = $self->get_data($key)

Retrieve custom data C<$value> associated with C<$key>.  Useful when a
rule needs to cache data for retrieval by subsequent rules.

=head3 set_data()

    $self->set_data($key, $value)

Associate custom data C<$value> with C<$key> for later retrieval.  See
also L<get_data()|/get_data()>.

=head3 validate()

    $self->validate()

Evaluate each rule on the passphrase specified by the
L<passphrase|/passphrase> attribute.  Rules are evaulated in the order
specified until a rule determines that the passphrase is too weak or
an error occurs.  After this method is called, the L<code|/code> and
L<message|/message> attributes will contain the results of the
validation.

=head2 Attributes

The attributes below can be accessed via methods of the form
get_I<attribute>() and set_I<attribute>().

=head3 code

HTTP status code to be returned at the end of the request.

=head3 debug

If TRUE, enable debugging to the Apache error log.

=head3 message

HTTP status message to be returned at the end of the request.

=head3 passphrase

The passphrase submitted by the user.

=head3 ruleset

The ruleset used to validate passphrases, either as a
L<Data::Passphrase::Ruleset|Data::Passphrase::Ruleset> object or as
a filename.  Defaults to F</etc/passphrase_rules>.

=head3 username

The username, which may be useful to rules.  Defaults to $r->user().

=head1 PROCEDURAL INTERFACE

=head3 validate_passphrase()

 $results = validate_passphrase \%attributes

Validate a passphrase.  Attributes passed in C<%attributes> are the
same as for the object-oriented interface.  C<$results> contains two
entries, C<code> and C<message>, whose values correspond to those
returned by the object-oriented attributes of the same names.

=head1 RULES SPECIFICATION

Passphrase rules may be specified directly as
L<Data::Passphrase::Rule|Data::Passphrase::Rule> objects or read
from a script file (see L</EXAMPLES>).  This script should return a
reference to a list of hash references, each of which is used to
construct a L<Data::Passphrase::Rule|Data::Passphrase::Rule>
object.  Hence, the following attributes have meaning to the module
and related programs:

=over

=item code

status code returned if passphrase fails this rule

=item message

status message returned if passphrase fails this rule

=item test

passphrase(s) used to test this rule

=item validate

code to do the validation

=back

When validating passphrases, each subroutine referenced by C<validate>
will be called in turn.  If every rule's validate subroutine succeeds,
a code of 200 and message of C<Passphrase accepted> will be returned;
otherwise, the code and message specified will be returned.

=head2 Validation

The validation subroutine is called with two arguments: an
Data::Passphrase object, and a reference to a hash of user-defined
data.  The Data::Passphrase class makes use of operator overloading to
allow some convenient syntax in the rules.  In string context, the
object evaluates to the text of the passphrase to avoid the need to
call L<get_passphrase()|/passphrase>.  In numeric context, the object
evaluates to the I<length> of the passphrase.

Using the L<set_data()/set_data()> method, a rule can stow away data
for use by a later rule.  The data is stored as key/value pairs in a
hash.  A reference to this hash is passed as the second argument to
the validate method; you can also use L<get_data()/get_data()> to get
to it.

Return values from the validate subroutine are interpreted as follows:

=over

=item -1

The candidate passphrase has passed this rule.  Return C<200
Passphrase accepted> without processing any subsequent rules.

=item 0

The candidate passphrase has failed this rule.  Return the error code
and message specified in the rule without processing any subsequent
rules.

=item 1

The candidate passphrase has passed this rule.  Continue with
subsequent rules and return C<200 Passphrase accepted> if the
passphrase passes all of them

=back

=head2 Status Codes

For the benefit of the HTTP services provided by
L<Data::Passphrase::Apache|Data::Passphrase::Apache>, most rules
should use codes in the 4xx range, which according to RFC 2616 denotes
a client error.  It's wise to avoid codes in the 40x or 41x range
because they already have common meanings.  Choosing a different code
for each rule makes it easier for applications to understand why a
passphrase was rejected, but it's not required.

=head2 Status Messages

The HTTP services provided by
L<Data::Passphrase::Apache|Data::Passphrase::Apache> build status
lines from the L<code|Data::Passphrase::Rule/code> and
L<message|Data::Passphrase::Rule/message> attributes.  The string
S<"Passphrase "> is prepended to the latter.  The message should
always be phrased as if the passphrase failed to pass the rule, for
example, C<is too short>.

=head2 Testing

The L<test|Data::Passphrase::Rule/test> attribute specifies one or
more passphrases that should fail the rule and is meant to be used by
an external program such as the included passphrase-test program.  It
may be represented in any way understandable by the test program, but
passphrase-test expects a single passphrase in a scalar, a reference
to an array of one or more passphrases, or a reference to a subroutine
that returns zero or more passphrases.  This attribute also serves as
documentation for the rule in the form of example passphrases the rule
is meant to disallow.

=head1 EXAMPLES

Here's an example with only one rule:

    Readonly my $MINIMUM_TOTAL_CHARACTERS => 15;
    
    return [
        {
            code     => 450,
            message  => 'is too short',
            test     => 'X' x ($MINIMUM_TOTAL_CHARACTERS - 1),
            validate => sub { $_[0] >= $MINIMUM_TOTAL_CHARACTERS },
        },
    ];
    __EOF__

This rule causes C<450 Passphrase is too short> to be returned for any
passphrase shorter than 15 characters.  The validate subroutine can
use C<$_[0]> as a comparator because in numeric context it evaluates
to the length of the passphrase even though it's an Data::Passphrase
object.  The test data is just a string of 14 Xs -- the
passphrase-test script will check to make sure this string results in
a 450.

For more examples, see the included F<passphrase_rules> file.

=head1 FILES

  /etc/passphrase_rules

=head1 AUTHOR

Andrew J. Korty <ajk@iu.edu>

=head1 SEE ALSO

Data::Passphrase::Apache(3), Data::Passphrase::Ruleset(3)
